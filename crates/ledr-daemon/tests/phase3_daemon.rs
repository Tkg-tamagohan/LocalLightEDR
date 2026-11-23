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
    PolicyRuleError, TwoLaneSender, WindowsBinaryInspector,
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
            || (allow
                && *self
                    .fail_wfp_add_permits
                    .lock()
                    .expect("lock fail_wfp_add_permits"))
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

fn default_test_config() -> DaemonConfig {
    DaemonConfig {
        pipe_name: unique_test_pipe_name(),
        ..DaemonConfig::default()
    }
}

fn start_test_engine(
    store: LedrStore,
    config: DaemonConfig,
    defense: Arc<dyn ActiveDefenseController>,
    notifier: Arc<dyn NotificationDispatcher>,
    inspector: Arc<dyn BinaryInspector>,
) -> Arc<DaemonEngine> {
    DaemonEngine::start_with_dependencies(
        store,
        SigmaEngine::default(),
        EarlyPruner::default(),
        config,
        defense,
        notifier,
        inspector,
    )
}

async fn send_process_start(sender: &TwoLaneSender, identity: ProcessIdentity, exe_path: &str) {
    send_process_start_with_sid(sender, identity, exe_path, None).await;
}

async fn send_process_start_with_sid(
    sender: &TwoLaneSender,
    identity: ProcessIdentity,
    exe_path: &str,
    user_sid: Option<&str>,
) {
    sender
        .send(SensorEvent::ProcessStart {
            identity,
            parent_pid: 4,
            exe_path: exe_path.to_string(),
            command_line: exe_path.to_string(),
            user_sid: user_sid.map(ToString::to_string),
        })
        .await
        .expect("send ProcessStart");
}

async fn send_network_connect(
    sender: &TwoLaneSender,
    pid: u32,
    dst_ip: IpAddr,
    dst_port: u16,
    domain_hint: Option<&str>,
    timestamp_ms: i64,
) {
    sender
        .send(SensorEvent::NetworkConnect {
            pid,
            protocol: 6,
            dst_ip,
            dst_port,
            domain_hint: domain_hint.map(ToString::to_string),
            timestamp_ms,
        })
        .await
        .expect("send NetworkConnect");
}

async fn send_dns_query(
    sender: &TwoLaneSender,
    pid: u32,
    query_name: &str,
    query_type: u16,
    resolved_ips: Vec<IpAddr>,
    timestamp_ms: i64,
) {
    sender
        .send(SensorEvent::DnsQuery {
            pid,
            query_name: query_name.to_string(),
            query_type,
            resolved_ips,
            timestamp_ms,
        })
        .await
        .expect("send DnsQuery");
}

async fn wait_pending_alerts(
    store: &LedrStore,
    expected: usize,
    timeout_ms: u64,
) -> Vec<AlertRecord> {
    assert!(
        wait_until(timeout_ms, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 50)
                .map(|v| v.len() == expected)
                .unwrap_or(false)
        })
        .await,
        "expected {expected} pending alert(s) within {timeout_ms}ms"
    );
    store
        .list_alerts(Some(AlertStatus::Pending), 50)
        .expect("list pending alerts")
}

fn make_net_rule(
    rule_id: &str,
    scope: RuleScope,
    exe_path_pattern: &str,
    sha256: Option<&str>,
    allowed_target: Option<&str>,
    created_at_ms: i64,
    created_by: &str,
) -> AllowlistRuleRecord {
    AllowlistRuleRecord {
        rule_id: rule_id.to_string(),
        scope,
        exe_path_pattern: exe_path_pattern.to_string(),
        sha256: sha256.map(ToString::to_string),
        signer_subject: None,
        root_thumbprint: None,
        allowed_target: allowed_target.map(ToString::to_string),
        created_by: created_by.to_string(),
        created_at_ms,
    }
}

async fn send_ipc_async(pipe_name: &str, req: IpcRequest) -> IpcResponse {
    let pipe = pipe_name.to_string();
    tokio::task::spawn_blocking(move || send_pipe_request(&pipe, &req))
        .await
        .expect("ipc task")
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

    let engine = start_test_engine(
        store.clone(),
        default_test_config(),
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
        send_process_start_with_sid(&sender, ident, exe, Some("S-1-5-21-1000")).await;
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
    send_network_connect(
        &sender,
        svchost.pid,
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        443,
        Some("windowsupdate.microsoft.com"),
        now_ms,
    )
    .await;
    send_network_connect(
        &sender,
        local_app.pid,
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
        8080,
        None,
        now_ms + 1,
    )
    .await;

    // Pre-emptively restricted processes connecting externally must freeze and emit High alerts.
    send_network_connect(
        &sender,
        dl_dropper.pid,
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
        443,
        Some("drop.example"),
        now_ms + 2,
    )
    .await;
    send_network_connect(
        &sender,
        node_proc.pid,
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 55)),
        443,
        Some("registry.example"),
        now_ms + 3,
    )
    .await;

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

    let engine = start_test_engine(
        store.clone(),
        default_test_config(),
        defense.clone(),
        notifier,
        inspector.clone(),
    );
    let sender = engine.sender();
    let now_ms = current_unix_ms();

    let unsigned_id = ProcessIdentity::new(5101, unix_ms_to_filetime(now_ms - 3_000));
    let signed_id = ProcessIdentity::new(5102, unix_ms_to_filetime(now_ms - 2_000));

    send_process_start(&sender, unsigned_id, unsigned_exe).await;
    send_process_start(&sender, signed_id, signed_exe).await;

    assert!(
        wait_until(1_000, || engine.active_process_table_len() == 2).await,
        "both processes seeded"
    );
    // General-path executables are NOT pre-emptively blocked on ProcessStart.
    assert_eq!(defense.active_wfp().len(), 0);

    // 1. Unsigned unknown process connects externally -> coupled WFP block + suspend.
    send_network_connect(
        &sender,
        unsigned_id.pid,
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        443,
        Some("api.unsigned.example"),
        now_ms,
    )
    .await;

    wait_pending_alerts(&store, 1, 2_000).await;
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
    send_network_connect(
        &sender,
        unsigned_id.pid,
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99)),
        443,
        Some("other.unsigned.example"),
        now_ms + 10,
    )
    .await;

    // 2. Signed unknown process connects -> AllowPermanent with signer + domain scope.
    send_network_connect(
        &sender,
        signed_id.pid,
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
        443,
        Some("updates.vendor.example"),
        now_ms + 20,
    )
    .await;

    wait_pending_alerts(&store, 1, 2_000).await;
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
    send_network_connect(
        &sender,
        signed_id.pid,
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11)),
        443,
        Some("cdn.vendor.example"),
        now_ms + 30,
    )
    .await;
    send_network_connect(
        &sender,
        signed_id.pid,
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77)),
        443,
        Some("untrusted.other.example"),
        now_ms + 40,
    )
    .await;

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

    let engine = start_test_engine(
        store.clone(),
        default_test_config(),
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
        send_process_start(&sender, id, exe).await;
    }
    assert!(wait_until(1_000, || engine.active_process_table_len() == 3).await);

    // Case A: add_wfp_app_rule fails -> suspend_process must NOT be invoked.
    defense.set_fail_wfp_add(true);
    send_network_connect(
        &sender,
        p_a.pid,
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        443,
        None,
        now_ms,
    )
    .await;
    wait_pending_alerts(&store, 1, 2_000).await;
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
    send_network_connect(
        &sender,
        p_b.pid,
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 12)),
        443,
        None,
        now_ms + 10,
    )
    .await;
    wait_pending_alerts(&store, 2, 2_000).await;
    assert!(defense.suspends().is_empty());
    assert_eq!(defense.added_wfp().len(), 1);
    assert_eq!(defense.removed_wfp(), vec![defense.added_wfp()[0].handle]);
    assert!(defense.active_wfp().is_empty());
    assert_eq!(engine.active_wfp_rule_count(), 0);

    // Case C: both succeed, then record_alert fails -> BOTH resume_process AND remove_wfp_rule
    // execute and dedup is cleared so retrying succeeds.
    defense.set_fail_suspend(false);
    engine.set_fail_record_alert_for_test(true);
    send_network_connect(
        &sender,
        p_c.pid,
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 88)),
        443,
        None,
        now_ms + 20,
    )
    .await;
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
    send_network_connect(
        &sender,
        p_c.pid,
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 88)),
        443,
        None,
        now_ms + 30,
    )
    .await;
    wait_pending_alerts(&store, 3, 2_000).await;
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

    let engine = start_test_engine(
        store.clone(),
        default_test_config(),
        defense.clone(),
        notifier,
        inspector.clone(),
    );
    let sender = engine.sender();
    let now_ms = current_unix_ms();

    // 1. Happy path AllowOnce
    let p_once = ProcessIdentity::new(5301, unix_ms_to_filetime(now_ms - 3_000));
    let exe_once = r"C:\Tools\once_app.exe";
    send_process_start(&sender, p_once, exe_once).await;
    send_network_connect(
        &sender,
        p_once.pid,
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        443,
        None,
        now_ms,
    )
    .await;

    wait_pending_alerts(&store, 1, 2_000).await;
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
    send_network_connect(
        &sender,
        p_once.pid,
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 44)),
        443,
        None,
        now_ms + 5,
    )
    .await;

    // 2. AllowOnce rollback when resume_process fails on a confirmed-live PID
    let live_pid = std::process::id();
    let p_live = ProcessIdentity::new(live_pid, unix_ms_to_filetime(now_ms - 2_000));
    let exe_live = r"C:\Users\alice\Downloads\live_fail_resume.exe";
    send_process_start(&sender, p_live, exe_live).await;
    send_network_connect(
        &sender,
        p_live.pid,
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 99)),
        443,
        None,
        now_ms + 10,
    )
    .await;

    wait_pending_alerts(&store, 1, 2_000).await;
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
        .upsert_policy_rule(&make_net_rule(
            "RULE-HARD-BLOCK",
            RuleScope::NetworkBlock,
            exe_blocked,
            None,
            None,
            now_ms,
            "user_quarantine",
        ))
        .expect("upsert block");
    assert!(engine.has_active_wfp_filter(exe_blocked, None, false));

    send_process_start(&sender, p_blocked, exe_blocked).await;
    send_network_connect(
        &sender,
        p_blocked.pid,
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        443,
        None,
        now_ms + 20,
    )
    .await;

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

    let engine = start_test_engine(
        store.clone(),
        default_test_config(),
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
        send_process_start(&sender, id, exe).await;
        send_network_connect(
            &sender,
            id.pid,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            443,
            None,
            now_ms,
        )
        .await;
    }

    wait_pending_alerts(&store, 2, 2_000).await;
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
        .upsert_rule(&make_net_rule(
            "RULE-CONFLICT-ALLOW",
            RuleScope::NetworkAllow,
            conflict_exe,
            Some(sha_conflict),
            None,
            now_ms - 1_000,
            "user_triage",
        ))
        .expect("seed allow");
    store
        .upsert_rule(&make_net_rule(
            "RULE-CONFLICT-BLOCK",
            RuleScope::NetworkBlock,
            conflict_exe,
            Some(sha_conflict),
            None,
            now_ms - 500,
            "user_quarantine",
        ))
        .expect("seed block");
    store
        .upsert_rule(&make_net_rule(
            "RULE-ALLOW-ONLY",
            RuleScope::NetworkAllow,
            allow_only_exe,
            Some(sha_allow),
            Some("198.51.100.20"),
            now_ms - 400,
            "user_triage",
        ))
        .expect("seed ip allow");

    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());
    inspector.register(conflict_exe, Some(sha_conflict), None);
    inspector.register(allow_only_exe, Some(sha_allow), None);

    let pipe_name = unique_test_pipe_name();
    let engine = start_test_engine(
        store.clone(),
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
                rule: make_net_rule(
                    "RULE-IP-OVERRIDE-BLOCK",
                    RuleScope::NetworkBlock,
                    allow_only_exe,
                    None,
                    Some("198.51.100.20"),
                    now_ms,
                    "user_policy",
                ),
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
/// SQLite, NRD severity escalation on `NetworkConnect`, and IPC `CheckDomainRisk` (`L-14`).
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

    let engine = start_test_engine(
        store.clone(),
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
        wait_until(3_000, || engine.nrd_entry_count() == 2
            && cache_path.exists())
        .await,
        "periodic NRD refresh must populate in-memory cache and persist disk cache"
    );

    let sender = engine.sender();
    let now_ms = current_unix_ms();
    let proc_id = ProcessIdentity::new(5501, unix_ms_to_filetime(now_ms - 1_000));
    send_process_start(&sender, proc_id, r"C:\Tools\nrd_probe.exe").await;
    send_dns_query(
        &sender,
        proc_id.pid,
        "sub.fresh-c2-2026.example",
        1,
        vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 66))],
        now_ms,
    )
    .await;
    send_dns_query(
        &sender,
        proc_id.pid,
        "example.com",
        1,
        vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
        now_ms + 1,
    )
    .await;
    send_network_connect(
        &sender,
        proc_id.pid,
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 66)),
        443,
        Some("sub.fresh-c2-2026.example"),
        now_ms + 2,
    )
    .await;

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

    let engine = start_test_engine(
        store.clone(),
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

    send_process_start(&sender, proc_id, exe_path).await;
    send_network_connect(
        &sender,
        proc_id.pid,
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        443,
        None,
        old_ts,
    )
    .await;

    wait_pending_alerts(&store, 1, 2_000).await;

    let expired = engine
        .expire_overdue_alerts(current_unix_ms())
        .expect("expire overdue");
    assert_eq!(expired, 1);

    let alerts = store
        .list_alerts(Some(AlertStatus::ExpiredSuspended), 10)
        .expect("list expired");
    assert_eq!(alerts.len(), 1);
    assert!(alerts[0].process_suspended);
    assert!(
        defense.resumes().is_empty(),
        "must never auto-resume on expiry"
    );
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
        .upsert_rule(&make_net_rule(
            "RULE-DL-ALLOW",
            RuleScope::NetworkAllow,
            exe_path,
            Some(sha),
            None,
            now_ms,
            "user_triage",
        ))
        .expect("seed allow");

    let engine = start_test_engine(store, default_test_config(), defense, notifier, inspector);
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
        wait_until(1_000, || !engine
            .has_active_wfp_filter(exe_path, None, false))
        .await,
        "Preemptive WFP block must be removed when the last running instance exits"
    );

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P3-10`: Materialized domain-scoped WFP filters (`DomainPolicy` Permit and Block)
/// survive unrelated `deploy_persisted_network_rules` reconciliations and are immediately removed
/// when their backing rule is deleted or overridden by a deny rule.
#[tokio::test]
async fn daemon_p3_10_domain_policy_filters_survive_unrelated_reconcile_and_purge_on_delete_or_deny(
) {
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
        .upsert_rule(&make_net_rule(
            "RULE-PS-DOMAIN-ALLOW",
            RuleScope::NetworkAllow,
            ps_exe,
            Some(ps_sha),
            Some("*.vendor.example"),
            now_ms,
            "user_policy",
        ))
        .expect("seed domain allow");
    store
        .upsert_rule(&make_net_rule(
            "RULE-APP-DOMAIN-BLOCK",
            RuleScope::NetworkBlock,
            app_exe,
            None,
            Some("*.evil-c2.example"),
            now_ms,
            "user_policy",
        ))
        .expect("seed domain block");

    let engine = start_test_engine(store, default_test_config(), defense, notifier, inspector);
    let sender = engine.sender();

    let ps_id = ProcessIdentity::new(6101, unix_ms_to_filetime(now_ms - 2_000));
    let app_id = ProcessIdentity::new(6102, unix_ms_to_filetime(now_ms - 1_000));
    for (id, exe) in [(ps_id, ps_exe), (app_id, app_exe)] {
        send_process_start(&sender, id, exe).await;
    }

    let allow_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
    let block_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77));
    send_network_connect(
        &sender,
        ps_id.pid,
        allow_ip,
        443,
        Some("api.vendor.example"),
        now_ms,
    )
    .await;
    send_network_connect(
        &sender,
        app_id.pid,
        block_ip,
        443,
        Some("gate.evil-c2.example"),
        now_ms + 5,
    )
    .await;

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
        .upsert_policy_rule(&make_net_rule(
            "RULE-UNRELATED-BLOCK",
            RuleScope::NetworkBlock,
            r"C:\Tools\unrelated.exe",
            None,
            None,
            now_ms + 10,
            "user_policy",
        ))
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

    let engine = start_test_engine(
        store.clone(),
        default_test_config(),
        defense.clone(),
        notifier,
        inspector.clone(),
    );
    let sender = engine.sender();
    let now_ms = current_unix_ms();

    // (a) Wildcard NetworkBlock saved before a general-path executable starts -> enforced at ProcessStart!
    engine
        .upsert_policy_rule(&make_net_rule(
            "RULE-WILD-UNTRUSTED",
            RuleScope::NetworkBlock,
            r"C:\Untrusted\*.exe",
            None,
            None,
            now_ms,
            "user_policy",
        ))
        .expect("upsert wildcard block");

    let stealer_exe = r"C:\Untrusted\stealer.exe";
    let stealer_id = ProcessIdentity::new(6201, unix_ms_to_filetime(now_ms - 500));
    send_process_start(&sender, stealer_id, stealer_exe).await;
    assert!(
        wait_until(2_000, || engine.has_active_wfp_filter(
            stealer_exe,
            None,
            false
        ))
        .await,
        "wildcard NetworkBlock must be applied immediately on ProcessStart for general-path exe"
    );

    // (b) Process already emitted NET_OUTBOUND (e.g. when WFP failed), then operator adds an
    //     IP-scoped NetworkBlock -> connecting via IPv4-mapped IPv6 MUST NOT be dedup-bypassed!
    let multi_exe = r"C:\Tools\multi_dest.exe";
    let multi_id = ProcessIdentity::new(6202, unix_ms_to_filetime(now_ms - 400));
    send_process_start(&sender, multi_id, multi_exe).await;
    assert!(wait_until(1_000, || engine.active_process_table_len() == 2).await);

    defense.set_fail_wfp_add(true);
    send_network_connect(
        &sender,
        multi_id.pid,
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        443,
        None,
        now_ms + 10,
    )
    .await;
    wait_pending_alerts(&store, 1, 2_000).await;

    defense.set_fail_wfp_add(false);
    let blocked_v4 = Ipv4Addr::new(198, 51, 100, 66);
    engine
        .upsert_policy_rule(&make_net_rule(
            "RULE-MULTI-IP-BLOCK",
            RuleScope::NetworkBlock,
            multi_exe,
            None,
            Some(&blocked_v4.to_string()),
            now_ms + 20,
            "user_policy",
        ))
        .expect("upsert IP block");

    // Connect over dual-stack IPv4-mapped IPv6 `::ffff:198.51.100.66`.
    send_network_connect(
        &sender,
        multi_id.pid,
        IpAddr::V6(blocked_v4.to_ipv6_mapped()),
        443,
        None,
        now_ms + 30,
    )
    .await;

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

    let engine = start_test_engine(
        store.clone(),
        default_test_config(),
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
        send_process_start(&sender, p, shared_exe).await;
    }
    send_network_connect(
        &sender,
        p1.pid,
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        443,
        None,
        now_ms,
    )
    .await;
    wait_pending_alerts(&store, 1, 2_000).await;
    let a1 = store.list_alerts(Some(AlertStatus::Pending), 10).unwrap()[0].clone();

    engine.set_fail_record_alert_for_test(true);
    send_network_connect(
        &sender,
        p2.pid,
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        443,
        None,
        now_ms + 5,
    )
    .await;
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
        send_process_start(&sender, p, dl_exe).await;
        send_network_connect(
            &sender,
            p.pid,
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 12)),
            443,
            None,
            now_ms + 20,
        )
        .await;
    }
    let pending_dl = wait_pending_alerts(&store, 2, 2_000).await;
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
        make_net_rule(
            "BAD-NO-IDENTITY",
            RuleScope::NetworkAllow,
            r"C:\Tools\app.exe",
            None,
            None,
            now_ms,
            "test",
        ),
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
        make_net_rule(
            "BAD-SHORT-SHA",
            RuleScope::NetworkAllow,
            r"C:\Tools\app.exe",
            Some("deadbeef"),
            None,
            now_ms,
            "test",
        ),
        make_net_rule(
            "BAD-BLOCK-LSASS",
            RuleScope::NetworkBlock,
            r"C:\Windows\System32\lsass.exe",
            None,
            None,
            now_ms,
            "test",
        ),
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

    let engine = start_test_engine(
        store.clone(),
        default_test_config(),
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
        send_process_start(&sender, p, exe).await;
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

    send_network_connect(
        &sender,
        p1.pid,
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 91)),
        443,
        Some("never-seen-before.example"),
        now_ms,
    )
    .await;
    send_network_connect(
        &sender,
        p2.pid,
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        443,
        Some("previously-seen.example"),
        now_ms + 5,
    )
    .await;

    engine.shutdown_and_flush().await.expect("shutdown");

    let alerts = store
        .list_alerts(Some(AlertStatus::Pending), 10)
        .expect("list");
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

    let engine = start_test_engine(
        store.clone(),
        default_test_config(),
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
        send_process_start(&sender, p, exe).await;
        send_network_connect(
            &sender,
            p.pid,
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 40)),
            443,
            None,
            now_ms,
        )
        .await;
    }

    let pending = wait_pending_alerts(&store, 2, 2_000).await;
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
    let p3 = ProcessIdentity::new(live_pid, unix_ms_to_filetime(now_ms + 1_000));
    let p4 = ProcessIdentity::new(6504, unix_ms_to_filetime(now_ms + 1_500));
    for p in [p3, p4] {
        send_process_start(&sender, p, exe2).await;
        send_network_connect(
            &sender,
            p.pid,
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 41)),
            443,
            None,
            now_ms + 2_000,
        )
        .await;
    }
    let pending2 = wait_pending_alerts(&store, 2, 2_000).await;
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
        Some((
            "CN=Broken Cert Vendor",
            "0000000000000000000000000000000000000000",
        )),
    );

    let engine = start_test_engine(
        store.clone(),
        default_test_config(),
        defense,
        notifier,
        inspector,
    );
    let sender = engine.sender();
    let now_ms = current_unix_ms();

    let p = ProcessIdentity::new(6601, unix_ms_to_filetime(now_ms - 1_000));
    send_process_start(&sender, p, exe).await;
    send_network_connect(
        &sender,
        p.pid,
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        443,
        None,
        now_ms,
    )
    .await;

    wait_pending_alerts(&store, 1, 2_000).await;
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
    send_network_connect(
        &sender,
        p.pid,
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 12)),
        443,
        None,
        now_ms + 10,
    )
    .await;

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
        .upsert_rule(&make_net_rule(
            "RULE-DNS-PS-ALLOW",
            RuleScope::NetworkAllow,
            ps_exe,
            Some(ps_sha),
            Some("*.packages.example"),
            now_ms,
            "user_policy",
        ))
        .expect("seed domain allow");
    store
        .upsert_rule(&make_net_rule(
            "RULE-DNS-PS-DENY-SUB",
            RuleScope::NetworkBlock,
            ps_exe,
            None,
            Some("bad.packages.example"),
            now_ms,
            "user_policy",
        ))
        .expect("seed overriding domain block");
    store
        .upsert_rule(&make_net_rule(
            "RULE-DNS-APP-BLOCK",
            RuleScope::NetworkBlock,
            app_exe,
            None,
            Some("*.c2-drop.example"),
            now_ms,
            "user_policy",
        ))
        .expect("seed app domain block");

    let engine = start_test_engine(store, default_test_config(), defense, notifier, inspector);
    let sender = engine.sender();

    let ps_id = ProcessIdentity::new(6701, unix_ms_to_filetime(now_ms - 2_000));
    let app_id = ProcessIdentity::new(6702, unix_ms_to_filetime(now_ms - 1_500));
    let svc_id = ProcessIdentity::new(6703, unix_ms_to_filetime(now_ms - 1_000));
    for (id, exe) in [(ps_id, ps_exe), (app_id, app_exe), (svc_id, svchost_exe)] {
        send_process_start(&sender, id, exe).await;
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
    send_dns_query(
        &sender,
        ps_id.pid,
        "cdn.packages.example.",
        1,
        vec![allow_ip, loopback_ip],
        now_ms,
    )
    .await;
    send_dns_query(
        &sender,
        ps_id.pid,
        "bad.packages.example",
        1,
        vec![deny_sub_ip],
        now_ms + 1,
    )
    .await;
    send_dns_query(
        &sender,
        app_id.pid,
        "stage1.c2-drop.example",
        1,
        vec![c2_ip],
        now_ms + 2,
    )
    .await;
    send_dns_query(
        &sender,
        svc_id.pid,
        "stage1.c2-drop.example",
        1,
        vec![c2_ip],
        now_ms + 3,
    )
    .await;

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
        .upsert_rule(&make_net_rule(
            "RULE-NODE-ALLOW",
            RuleScope::NetworkAllow,
            node_exe,
            Some(node_sha),
            None,
            now_ms,
            "user_policy",
        ))
        .expect("seed node allow");

    let engine = start_test_engine(
        store,
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
        send_process_start(&sender, id, exe).await;
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
    send_process_start(&sender, node_id, node_exe).await;
    send_network_connect(
        &sender,
        node_id.pid,
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        443,
        None,
        now_ms + 700,
    )
    .await;
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
        wait_until(1_000, || engine
            .has_active_wfp_filter(node_exe, None, false))
        .await,
        "startup-pinned node.exe Preemptive block must re-arm when AllowOnce instance exits"
    );

    // Upserting a wildcard app-wide NetworkAllow for powershell.exe overrides its startup Preemptive block.
    engine
        .upsert_policy_rule(&make_net_rule(
            "RULE-PS-ALLOW",
            RuleScope::NetworkAllow,
            r"C:\Windows\System32\WindowsPowerShell\*\powershell.exe",
            Some(ps_sha),
            None,
            now_ms + 1_000,
            "user_policy",
        ))
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

    let engine = start_test_engine(
        store.clone(),
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
    send_process_start(&sender, ps1, ps_exe).await;
    send_network_connect(
        &sender,
        ps1.pid,
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        443,
        None,
        now_ms,
    )
    .await;
    wait_pending_alerts(&store, 1, 2_000).await;
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
    send_process_start(&sender, ps2, ps_exe).await;
    assert!(wait_until(1_000, || engine.active_process_table_len() >= 2).await);
    assert!(
        !engine.has_active_wfp_filter(ps_exe, None, false),
        "starting sibling P2 must NOT re-arm app-wide Preemptive block while P1 has AllowOnce"
    );

    // P1 follow-up connect remains ALLOWED.
    send_network_connect(
        &sender,
        ps1.pid,
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
        443,
        None,
        now_ms + 5,
    )
    .await;

    // P2 external connect -> P2 MUST suspend and emit alert with deferred WFP flag,
    // without adding an app-wide WFP block that would sever P1!
    send_network_connect(
        &sender,
        ps2.pid,
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 11)),
        443,
        None,
        now_ms + 10,
    )
    .await;
    wait_pending_alerts(&store, 1, 2_000).await;
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
        send_process_start(&sender, p, dl_exe).await;
    }
    assert!(wait_until(1_000, || engine.has_active_wfp_filter(dl_exe, None, false)).await);

    send_network_connect(
        &sender,
        dl1.pid,
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 30)),
        443,
        None,
        now_ms + 30,
    )
    .await;
    wait_pending_alerts(&store, 1, 2_000).await;
    let a_dl1 = store.list_alerts(Some(AlertStatus::Pending), 10).unwrap()[0].clone();
    engine
        .resolve_alert(&a_dl1.alert_id, AlertDecision::AllowOnce)
        .expect("AllowOnce dl1");
    assert!(!engine.has_active_wfp_filter(dl_exe, None, false));

    // dl3 starts while dl1 holds AllowOnce -> no Preemptive block added yet.
    send_process_start(&sender, dl3, dl_exe).await;
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
        .upsert_rule(&make_net_rule(
            "RULE-SHARED-BLOCK",
            RuleScope::NetworkBlock,
            ps_exe,
            None,
            Some("blocked.example"),
            now_ms,
            "user_policy",
        ))
        .expect("seed domain block");
    store
        .upsert_rule(&make_net_rule(
            "RULE-SHARED-ALLOW",
            RuleScope::NetworkAllow,
            ps_exe,
            Some(ps_sha),
            Some("api.example"),
            now_ms,
            "user_policy",
        ))
        .expect("seed domain allow");

    let engine = start_test_engine(store, default_test_config(), defense, notifier, inspector);
    let sender = engine.sender();
    let ps_id = ProcessIdentity::new(7201, unix_ms_to_filetime(now_ms - 1_000));
    send_process_start(&sender, ps_id, ps_exe).await;

    let shared_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50));
    send_dns_query(
        &sender,
        ps_id.pid,
        "blocked.example",
        1,
        vec![shared_ip],
        now_ms,
    )
    .await;
    send_dns_query(
        &sender,
        ps_id.pid,
        "api.example",
        1,
        vec![shared_ip],
        now_ms + 1,
    )
    .await;

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
    let engine = start_test_engine(
        store.clone(),
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
    let valid_block = make_net_rule(
        "RULE-SYNC-TEST",
        RuleScope::NetworkBlock,
        app_exe,
        None,
        None,
        now_ms,
        "user_policy",
    );
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
    let failing_new = make_net_rule(
        "RULE-FAIL-ADD",
        RuleScope::NetworkBlock,
        r"C:\Tools\never_persisted.exe",
        None,
        None,
        now_ms,
        "user_policy",
    );
    let fail_resp = send_ipc_async(&pipe_name, IpcRequest::UpsertRule { rule: failing_new }).await;
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
    let del_err = send_ipc_async(
        &pipe_name,
        IpcRequest::DeleteRule {
            rule_id: "RULE-SYNC-TEST".to_string(),
        },
    )
    .await;
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

    let swap_rule = make_net_rule(
        "RULE-SCOPE-SWAP",
        RuleScope::NetworkAllow,
        dl_exe,
        Some(dl_sha),
        None,
        now_ms,
        "user_policy",
    );
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
    let err_upd = engine.upsert_policy_rule(&make_net_rule(
        "RULE-SYNC-TEST",
        RuleScope::NetworkAllow,
        app_exe,
        Some(app_sha),
        None,
        now_ms,
        "user_policy",
    ));
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
    wait_pending_alerts(&store, 1, 2_000).await;
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
        store
            .list_rules(Some(RuleScope::NetworkAllow))
            .unwrap()
            .into_iter()
            .all(|r| r.exe_path_pattern != dl_retry_exe),
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
    // Create a general exe whose connect WFP add fails initially (alert emitted, no WFP filter),
    // then TerminateAndBlock { add_block_rule: true } fails WFP add -> keeps alert Pending!
    let term2_exe = r"C:\Tools\term2_sync_fail.exe";
    let term2_proc = ProcessIdentity::new(7304, unix_ms_to_filetime(now_ms - 250));
    let hp_before = engine.metrics().high_priority_processed;
    send_process_start(&engine.sender(), term2_proc, term2_exe).await;
    assert!(wait_until(1_000, || engine.metrics().high_priority_processed > hp_before).await);
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
    wait_pending_alerts(&store, 2, 2_000).await;
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

    let engine = start_test_engine(
        store.clone(),
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

    wait_pending_alerts(&store, 1, 2_000).await;
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
        wait_until(1_000, || classified
            .classifier()
            .is_steady_pid(unknown_id.pid))
        .await,
        "AllowOnce PID must become steady after evaluation"
    );
    engine
        .upsert_policy_rule(&make_net_rule(
            "RULE-INVALIDATE-STEADY",
            RuleScope::NetworkBlock,
            r"C:\Tools\unrelated_policy.exe",
            None,
            None,
            now_ms + 900,
            "user_policy",
        ))
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
            .upsert_rule(&make_net_rule(
                id,
                RuleScope::NetworkAllow,
                exe,
                Some(sha),
                None,
                now_ms,
                "user_policy",
            ))
            .expect("seed allow");
    }

    let engine = start_test_engine(
        store.clone(),
        default_test_config(),
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
    send_process_start(&sender, p_dl, dl_exe).await;
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
    send_process_start(&sender, p_gen, gen_exe).await;
    assert!(wait_until(1_000, || engine.active_process_table_len() == 2).await);
    assert!(engine.has_active_wfp_filter(gen_exe, None, true));

    inspector.register(gen_exe, Some(sha_evil_gen), None);
    send_network_connect(
        &sender,
        p_gen.pid,
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        443,
        Some("c2.example"),
        now_ms + 20,
    )
    .await;
    assert!(
        wait_until(2_000, || {
            !engine.has_active_wfp_filter(gen_exe, None, true)
                && engine.has_active_wfp_filter(gen_exe, None, false)
                && defense.suspends().contains(&p_gen)
        })
        .await,
        "replaced general binary connecting externally must revoke stale Permit and enter coupled containment"
    );
    assert_eq!(
        store
            .list_alerts(Some(AlertStatus::Pending), 10)
            .unwrap()
            .len(),
        1
    );

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
        .upsert_rule(&make_net_rule(
            "RULE-DOMAIN-TRUSTED",
            RuleScope::NetworkAllow,
            r"C:\Tools\*.exe",
            Some(allow_sha),
            Some("trusted.example"),
            now_ms,
            "user_policy",
        ))
        .expect("seed trusted domain rule");

    let engine = start_test_engine(
        store.clone(),
        default_test_config(),
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
        send_process_start(&sender, p, exe).await;
    }

    let trusted_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77));
    // 1. Isolated connect with domain_hint and NO conflicting DnsQuery preserves domain_hint!
    let iso_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77));
    send_network_connect(
        &sender,
        p_isolated.pid,
        iso_ip,
        443,
        Some("trusted.example"),
        now_ms,
    )
    .await;

    // 2. Now p_good resolves trusted.example -> trusted_ip.
    send_dns_query(
        &sender,
        p_good.pid,
        "trusted.example",
        1,
        vec![trusted_ip],
        now_ms + 5,
    )
    .await;
    send_network_connect(
        &sender,
        p_good.pid,
        trusted_ip,
        443,
        Some("trusted.example"),
        now_ms + 10,
    )
    .await;

    // 3. p_hijack NEVER queried trusted.example, yet receives poisoned domain_hint -> Layer 2
    //    MUST drop domain_hint and quarantine p_hijack!
    send_network_connect(
        &sender,
        p_hijack.pid,
        trusted_ip,
        443,
        Some("trusted.example"),
        now_ms + 15,
    )
    .await;

    let alerts = wait_pending_alerts(&store, 1, 2_000).await;
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
    let engine = start_test_engine(
        store.clone(),
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
    send_process_start(&sender, ps_proc, ps_exe).await;
    let drop_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77));
    send_dns_query(
        &sender,
        ps_proc.pid,
        "blocked-drop.example",
        1,
        vec![drop_ip],
        now_ms,
    )
    .await;
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

    wait_pending_alerts(&store, 1, 2_000).await;
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

    let engine = start_test_engine(
        store,
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

    let engine = start_test_engine(
        store.clone(),
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

    let engine = start_test_engine(
        store.clone(),
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

/// `DAEMON-P3-29` (`Thread 9`, `BUG_0004`): Multiple active instances of the same executable must
/// NEVER guess `candidates[0]`, misattribute via prior `(exe, ip, port)` connects, or fabricate
/// `network_events` when attributing `WfpDropEvent`:
/// - Ambiguous multi-instance drops emit a deduplicated app-level alert (`process_instance_id = None`,
///   `process_suspended = false`, `"attribution": "app_level_ambiguous"`) with zero suspensions.
/// - Sequential access by another instance to the same `(dst_ip, dst_port)` after an earlier
///   instance was quarantined is NOT swallowed by the earlier instance's dedup and surfaces an
///   `app_level_ambiguous` alert.
#[tokio::test]
async fn daemon_p3_29_wfp_drop_multi_instance_disambiguation_and_ambiguous_app_alert() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());
    let ps_exe = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    let tool_exe = r"C:\Tools\worker.exe";

    let engine = start_test_engine(
        store.clone(),
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
        store
            .list_alerts(Some(AlertStatus::Pending), 10)
            .unwrap()
            .len(),
        1
    );

    // AllowOnce lifts WFP block and marks active candidate instances so pre-emptive block isn't re-armed.
    engine
        .resolve_alert(&ambig_alert.alert_id, AlertDecision::AllowOnce)
        .expect("AllowOnce on app-level ambiguous alert");
    assert!(!engine.has_active_wfp_filter(ps_exe, None, false));

    // 2. Two concurrent instances of `tool.exe` (`q1`, `q2`): `q2` connects to (203.0.113.99, 8443)
    //    first, triggering suspension + app-wide WFP containment + `q2_alert`. When `q1` hits the
    //    same `(dst_ip, dst_port)` shortly after (`WfpDropEvent` with no PID), it MUST NOT be
    //    falsely attributed to `q2` and silenced by `q2`'s dedup — it must emit an app-level alert.
    let q1 = ProcessIdentity::new(8201, unix_ms_to_filetime(now_ms - 800));
    let q2 = ProcessIdentity::new(8202, unix_ms_to_filetime(now_ms - 700));
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

    let shared_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 99));
    engine
        .sender()
        .send(SensorEvent::NetworkConnect {
            pid: q2.pid,
            protocol: 6,
            dst_ip: shared_ip,
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
    assert!(q2_alert.process_suspended);
    assert!(engine.has_active_wfp_filter(tool_exe, None, false));

    // Sibling `q1` connects to the same `(shared_ip, 8443)` and gets blocked by the app-wide WFP
    // filter -> WfpDropEvent arrives shortly after -> MUST emit an `app_level_ambiguous` alert
    // rather than being misattributed to `q2` and swallowed by `q2`'s dedup!
    assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
        os_filter_id: 20,
        rule_handle: 20,
        exe_path: tool_exe.to_string(),
        protocol: 6,
        dst_ip: shared_ip,
        dst_port: 8443,
        timestamp_ms: now_ms + 700,
    }));
    assert!(
        wait_until(1_500, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 10)
                .map(|a| a.len() == 2)
                .unwrap_or(false)
        })
        .await,
        "subsequent sibling WfpDropEvent to same destination must surface as app_level_ambiguous alert"
    );
    let alerts = store.list_alerts(Some(AlertStatus::Pending), 10).unwrap();
    let app_alert = alerts
        .iter()
        .find(|a| a.alert_id != q2_alert.alert_id)
        .expect("app-level alert present");
    assert_eq!(app_alert.process_instance_id, None);
    assert!(!app_alert.process_suspended);
    let app_ctx: serde_json::Value = serde_json::from_str(&app_alert.context_json).unwrap();
    assert_eq!(app_ctx["attribution"], "app_level_ambiguous");
    assert_eq!(defense.suspends(), vec![q2]);

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P3-30` (`Threads 10, 14, 18`): Unrelated pre-existing WFP reconcile failures do not
/// poison `UpsertRule` / `DeleteRule` / `AllowPermanent` / `TerminateAndBlock`; failed
/// `DeleteRule` on a domain block rule restores both SQLite and partially-removed `DomainPolicy`
/// WFP filters without breaking sibling containment bindings.
#[tokio::test]
async fn daemon_p3_30_wfp_scoping_ignores_unrelated_failure_and_restores_domain_block_on_rollback()
{
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
        .upsert_rule(&make_net_rule(
            "R-PRE-BROKEN",
            RuleScope::NetworkBlock,
            broken_exe,
            None,
            None,
            now_ms,
            "test",
        ))
        .expect("seed broken rule");
    defense.add_fail_wfp_exe("broken_preexisting.exe");

    let pipe_name = unique_test_pipe_name();
    let engine = start_test_engine(
        store.clone(),
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
    let ack2 = send_ipc_async(
        &pipe_name,
        IpcRequest::DeleteRule {
            rule_id: "R-HEALTHY".to_string(),
        },
    )
    .await;
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
    wait_pending_alerts(&store, 1, 1_500).await;
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
    wait_pending_alerts(&store, 1, 1_500).await;
    let al_term = store.list_alerts(Some(AlertStatus::Pending), 10).unwrap()[0].clone();
    engine
        .resolve_alert(
            &al_term.alert_id,
            AlertDecision::TerminateAndBlock {
                add_block_rule: true,
            },
        )
        .expect("TerminateAndBlock succeeds even while unrelated broken rule fails");

    // 2. Partial DomainPolicy delete failure rolls back SQLite AND restores deleted DomainPolicy IP.
    let dom_rule = make_net_rule(
        "R-DOM-ROLLBACK",
        RuleScope::NetworkBlock,
        dom_exe,
        None,
        Some("evil-rollback.example"),
        now_ms,
        "test",
    );
    engine
        .upsert_policy_rule(&dom_rule)
        .expect("upsert dom block");

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
    let engine = start_test_engine(
        store.clone(),
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
    let bad_rule = make_net_rule(
        "R-BAD-CIDR",
        RuleScope::NetworkAllow,
        app_exe,
        Some(app_hash.as_str()),
        Some("198.51.100.0/33"),
        now_ms,
        "test",
    );
    let bad_resp = send_ipc_async(&pipe_name, IpcRequest::UpsertRule { rule: bad_rule }).await;
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
    let allow_resp = send_ipc_async(&pipe_name, IpcRequest::UpsertRule { rule: allow_rule }).await;
    assert!(matches!(allow_resp, IpcResponse::Ack { .. }));

    let block_rule = make_net_rule(
        "R-CIDR-BLOCK",
        RuleScope::NetworkBlock,
        app_exe,
        None,
        Some("198.51.100.128/25"),
        now_ms,
        "test",
    );
    let block_resp = send_ipc_async(&pipe_name, IpcRequest::UpsertRule { rule: block_rule }).await;
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
        wait_until(1_500, || engine.has_active_wfp_filter(
            app_exe,
            Some(allowed_ip),
            true
        ))
        .await,
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

/// `DAEMON-P3-32` (`PRRT_..._WNKR` & `WNMN`): Unrelated PID DNS queries do NOT prematurely
/// wake a parked `WfpDropEvent` during `wfp_drop_dns_grace_ms`; real candidate DNS authorizes it;
/// and ambiguous CIDR/wildcard `AllowedByRule` installs a concrete IP WFP Permit or alerts with
/// `LEDR-NET-POLICY-PERMIT-FAILED` on BFE failure.
#[tokio::test]
async fn daemon_p3_32_wfp_drop_ignores_unrelated_pid_dns_and_allows_ambiguous_cidr() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let ps_exe = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    let chrome_exe = r"C:\Program Files\Google\Chrome\Application\chrome.exe";
    let ps_hash = "d".repeat(64);
    let chrome_hash = "e".repeat(64);
    inspector.register(ps_exe, Some(&ps_hash), None);
    inspector.register(chrome_exe, Some(&chrome_hash), None);

    let now_ms = current_unix_ms();
    store
        .upsert_rule(&make_net_rule(
            "R-PS-DOM-ALLOW",
            RuleScope::NetworkAllow,
            ps_exe,
            Some(ps_hash.as_str()),
            Some("api.realps.example"),
            now_ms,
            "test",
        ))
        .expect("seed ps domain allow");
    store
        .upsert_rule(&AllowlistRuleRecord {
            rule_id: "R-PS-CIDR-ALLOW".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: ps_exe.to_string(),
            sha256: Some(ps_hash),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("198.51.100.0/24".to_string()),
            created_at_ms: now_ms + 1,
            created_by: "test".to_string(),
        })
        .expect("seed ps cidr allow");

    let engine = start_test_engine(
        store.clone(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            preemptive_startup_executables: vec![ps_exe.to_string()],
            wfp_drop_dns_grace_ms: 400,
            ..DaemonConfig::default()
        },
        defense.clone(),
        notifier,
        inspector,
    );

    let ps1 = ProcessIdentity::new(8501, unix_ms_to_filetime(now_ms - 500));
    let ch1 = ProcessIdentity::new(8502, unix_ms_to_filetime(now_ms - 500));
    for (proc_id, exe) in [(ps1, ps_exe), (ch1, chrome_exe)] {
        engine
            .sender()
            .send(SensorEvent::ProcessStart {
                identity: proc_id,
                parent_pid: 4,
                exe_path: exe.to_string(),
                command_line: exe.to_string(),
                user_sid: None,
            })
            .await
            .expect("start proc");
    }
    assert!(wait_until(1_000, || engine.active_process_table_len() == 2).await);

    // Part A: Unrelated Chrome DNS for `api.realps.example` -> target_ip MUST NOT flush ps1's
    // parked WfpDropEvent early. Only ps1's own DnsQuery authorizes it (0 alerts, 0 suspends).
    let dom_ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 77));
    assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
        os_filter_id: 1,
        rule_handle: 1,
        exe_path: ps_exe.to_string(),
        protocol: 6,
        dst_ip: dom_ip,
        dst_port: 443,
        timestamp_ms: now_ms + 10,
    }));

    tokio::time::sleep(Duration::from_millis(20)).await;
    engine
        .sender()
        .send(SensorEvent::DnsQuery {
            pid: ch1.pid,
            query_name: "api.realps.example".to_string(),
            query_type: 1,
            resolved_ips: vec![dom_ip],
            timestamp_ms: now_ms + 20,
        })
        .await
        .expect("chrome dns");
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert!(
        !engine.has_active_wfp_filter(ps_exe, Some(dom_ip), true),
        "unrelated chrome DnsQuery must not authorize powershell WfpDropEvent"
    );
    assert!(defense.suspends().is_empty());

    // Now ps1 emits the real DnsQuery well inside the 400ms grace window.
    engine
        .sender()
        .send(SensorEvent::DnsQuery {
            pid: ps1.pid,
            query_name: "api.realps.example".to_string(),
            query_type: 1,
            resolved_ips: vec![dom_ip],
            timestamp_ms: now_ms + 50,
        })
        .await
        .expect("ps1 dns");
    assert!(
        wait_until(1_000, || {
            engine.has_active_wfp_filter(ps_exe, Some(dom_ip), true)
        })
        .await,
        "ps1 DnsQuery must flush parked WfpDropEvent and install DomainPolicy permit"
    );
    assert!(defense.suspends().is_empty());
    assert!(store.list_alerts(None, 20).unwrap().is_empty());

    // Part B: Start a second powershell instance so PID attribution is ambiguous (`candidates.len() == 2`).
    let ps2 = ProcessIdentity::new(8503, unix_ms_to_filetime(now_ms - 400));
    engine
        .sender()
        .send(SensorEvent::ProcessStart {
            identity: ps2,
            parent_pid: 4,
            exe_path: ps_exe.to_string(),
            command_line: ps_exe.to_string(),
            user_sid: None,
        })
        .await
        .expect("start ps2");
    assert!(wait_until(1_000, || engine.active_process_table_len() == 3).await);

    let cidr_ip_ok = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
    assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
        os_filter_id: 2,
        rule_handle: 2,
        exe_path: ps_exe.to_string(),
        protocol: 6,
        dst_ip: cidr_ip_ok,
        dst_port: 443,
        timestamp_ms: now_ms + 100,
    }));
    assert!(
        wait_until(1_500, || {
            engine.has_active_wfp_filter(ps_exe, Some(cidr_ip_ok), true)
        })
        .await,
        "ambiguous AllowedByRule CIDR must materialize concrete IP WFP permit"
    );
    assert!(store.list_alerts(None, 20).unwrap().is_empty());
    assert!(defense.suspends().is_empty());

    // Now simulate BFE permit installation failure on another CIDR IP -> must alert instead of silently dropping!
    defense.set_fail_wfp_add_permits(true);
    let cidr_ip_fail = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20));
    assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
        os_filter_id: 3,
        rule_handle: 3,
        exe_path: ps_exe.to_string(),
        protocol: 6,
        dst_ip: cidr_ip_fail,
        dst_port: 443,
        timestamp_ms: now_ms + 150,
    }));
    assert!(
        wait_until(1_500, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 20)
                .map(|v| {
                    v.iter()
                        .any(|a| a.rule_id == "LEDR-NET-POLICY-PERMIT-FAILED")
                })
                .unwrap_or(false)
        })
        .await,
        "failed permit installation under AllowedByRule must raise LEDR-NET-POLICY-PERMIT-FAILED alert"
    );
    let permit_alert = store
        .list_alerts(Some(AlertStatus::Pending), 20)
        .unwrap()
        .into_iter()
        .find(|a| a.rule_id == "LEDR-NET-POLICY-PERMIT-FAILED")
        .unwrap();
    let ctx: serde_json::Value =
        serde_json::from_str(&permit_alert.context_json).expect("context_json");
    assert_eq!(ctx["attribution"], serde_json::json!("app_level_ambiguous"));
    assert!(ctx["wfp_permit_error"].as_str().is_some());
    assert!(defense.suspends().is_empty());

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P3-33` (`PRRT_..._WNNr`): Telemetry flood never starves `wfp_drop_rx`, and bursting past
/// `wfp_drop_tx` capacity overflows losslessly into `wfp_drop_overflow` without dropping alerts.
#[tokio::test]
async fn daemon_p3_33_wfp_drop_not_starved_by_telemetry_burst_and_overflow() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let app_exe = r"C:\Temp\drop_burst.exe";
    let now_ms = current_unix_ms();

    let engine = start_test_engine(
        store.clone(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            high_priority_capacity: 4,
            telemetry_capacity: 64,
            preemptive_startup_executables: vec![app_exe.to_string()],
            wfp_drop_dns_grace_ms: 0,
            ..DaemonConfig::default()
        },
        defense.clone(),
        notifier,
        inspector,
    );

    // Start two instances of `app_exe` (multi-instance -> AppWfpAlertDedup per `(exe, dst_ip)`)
    // plus one instance each of `drop_burst_9..12.exe` so every queued/coalesced drop has
    // active process attribution in `ActiveProcessTable`.
    for (idx, exe) in [
        (8601, app_exe.to_string()),
        (8602, app_exe.to_string()),
        (8609, r"C:\Temp\drop_burst_9.exe".to_string()),
        (8610, r"C:\Temp\drop_burst_10.exe".to_string()),
        (8611, r"C:\Temp\drop_burst_11.exe".to_string()),
        (8612, r"C:\Temp\drop_burst_12.exe".to_string()),
    ] {
        engine
            .sender()
            .send(SensorEvent::ProcessStart {
                identity: ProcessIdentity::new(idx, unix_ms_to_filetime(now_ms - 500)),
                parent_pid: 4,
                exe_path: exe.clone(),
                command_line: exe,
                user_sid: None,
            })
            .await
            .expect("start burst proc");
    }
    assert!(wait_until(1_000, || engine.active_process_table_len() == 6).await);

    let classified = engine.classified_sender();
    classified.classifier().mark_steady(9999);

    // Part A: Saturate Telemetry continuously while injecting a WfpDropEvent -> must not starve.
    let stop_flood = Arc::new(AtomicBool::new(false));
    let stop_c = Arc::clone(&stop_flood);
    let sender_c = classified.clone();
    let flood_task = tokio::spawn(async move {
        let mut seq = 0i64;
        while !stop_c.load(Ordering::Relaxed) {
            let _ = sender_c
                .send(SensorEvent::DnsQuery {
                    pid: 9999,
                    query_name: format!("flood-{seq}.example"),
                    query_type: 1,
                    resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))],
                    timestamp_ms: now_ms + seq,
                })
                .await;
            seq = seq.wrapping_add(1);
            if seq % 32 == 0 {
                tokio::task::yield_now().await;
            }
        }
    });

    // Wait briefly so Telemetry queue stays full before injecting WfpDropEvent.
    tokio::time::sleep(Duration::from_millis(30)).await;
    let first_drop_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200));
    assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
        os_filter_id: 1,
        rule_handle: 1,
        exe_path: app_exe.to_string(),
        protocol: 6,
        dst_ip: first_drop_ip,
        dst_port: 443,
        timestamp_ms: now_ms + 1,
    }));

    assert!(
        wait_until(1_500, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 10)
                .map(|v| !v.is_empty())
                .unwrap_or(false)
        })
        .await,
        "WfpDropEvent must be handled promptly even under continuous Telemetry saturation"
    );
    stop_flood.store(true, Ordering::Release);
    flood_task.await.expect("join telemetry flood");

    // Part B: Burst 12 distinct WfpDropEvents past `high_priority_capacity = 4` while the worker
    // drains concurrently, verifying the bounded overflow fallback queue (`wfp_drop_overflow_pushed() > 0`)
    // absorbs the burst without dropping any alert. Deterministic verification of same-app
    // overwrite coalescing (`wfp_drop_overflow_coalesced() > 0`) and latest-destination payload
    // retention is covered by `DAEMON-P3-44` and `DAEMON-P3-44A`.
    for i in 1u8..=12 {
        let burst_exe = if i <= 8 {
            app_exe.to_string()
        } else {
            format!(r"C:\Temp\drop_burst_{i}.exe")
        };
        assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
            os_filter_id: u64::from(i) + 10,
            rule_handle: u64::from(i) + 10,
            exe_path: burst_exe,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, i)),
            dst_port: 8443,
            timestamp_ms: now_ms + 100 + i64::from(i),
        }));
    }
    assert!(
        engine.wfp_drop_overflow_pushed() > 0,
        "burst >4 WfpDropEvents with capacity=4 must exercise bounded overflow queue"
    );
    wait_pending_alerts(&store, 13, 2_500).await;

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P3-34` (`PRRT_..._WNJE`): Repeated WFP failures on a rule that IS part of an IPC
/// `UpsertRule` mutation must NOT be suppressed by prior startup failures; IPC returns
/// `WFP_SYNC_ERROR` and rolls back the SQLite edit.
#[tokio::test]
async fn daemon_p3_34_prior_failed_rule_update_still_returns_firewall_sync_error() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let fail_exe = r"C:\Temp\repeat_fail_rule.exe";
    defense.add_fail_wfp_exe("repeat_fail_rule.exe");

    let now_ms = current_unix_ms();
    store
        .upsert_rule(&AllowlistRuleRecord {
            rule_id: "R-FAIL-REPEAT".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: fail_exe.to_string(),
            sha256: None,
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("203.0.113.50".to_string()),
            created_at_ms: now_ms,
            created_by: "seed".to_string(),
        })
        .expect("seed failing block rule");

    let pipe_name = unique_test_pipe_name();
    let engine = start_test_engine(
        store.clone(),
        DaemonConfig {
            pipe_name: pipe_name.clone(),
            dev_mode_bypass_ui_auth: true,
            ..DaemonConfig::default()
        },
        defense,
        notifier,
        inspector,
    );
    let server = start_ipc_server(Arc::clone(&engine)).expect("start ipc");

    // 1. Re-upserting the SAME failing target (`203.0.113.50`) with updated metadata must still
    //    surface `WFP_SYNC_ERROR` and roll back `created_by` to `"seed"`.
    let same_target_update = AllowlistRuleRecord {
        rule_id: "R-FAIL-REPEAT".to_string(),
        scope: RuleScope::NetworkBlock,
        exe_path_pattern: fail_exe.to_string(),
        sha256: None,
        signer_subject: None,
        root_thumbprint: None,
        allowed_target: Some("203.0.113.50".to_string()),
        created_at_ms: now_ms + 10,
        created_by: "ui-retry".to_string(),
    };
    let resp1 = send_ipc_async(
        &pipe_name,
        IpcRequest::UpsertRule {
            rule: same_target_update,
        },
    )
    .await;
    assert!(
        matches!(&resp1, IpcResponse::Error { code, .. } if code == "WFP_SYNC_ERROR"),
        "re-upserting failing rule with same target must still return WFP_SYNC_ERROR, got {resp1:?}"
    );
    assert_eq!(
        store.get_rule("R-FAIL-REPEAT").unwrap().unwrap().created_by,
        "seed"
    );

    // 2. Updating the rule to a different failing IP (`203.0.113.51`) must likewise fail and
    //    preserve `"203.0.113.50"` in SQLite.
    let new_target_update = AllowlistRuleRecord {
        rule_id: "R-FAIL-REPEAT".to_string(),
        scope: RuleScope::NetworkBlock,
        exe_path_pattern: fail_exe.to_string(),
        sha256: None,
        signer_subject: None,
        root_thumbprint: None,
        allowed_target: Some("203.0.113.51".to_string()),
        created_at_ms: now_ms + 20,
        created_by: "ui-edit".to_string(),
    };
    let resp2 = send_ipc_async(
        &pipe_name,
        IpcRequest::UpsertRule {
            rule: new_target_update,
        },
    )
    .await;
    assert!(
        matches!(&resp2, IpcResponse::Error { code, .. } if code == "WFP_SYNC_ERROR"),
        "updating failing rule target must return WFP_SYNC_ERROR, got {resp2:?}"
    );
    assert_eq!(
        store
            .get_rule("R-FAIL-REPEAT")
            .unwrap()
            .unwrap()
            .allowed_target
            .as_deref(),
        Some("203.0.113.50")
    );

    drop(server);
    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P3-35` (`SEC_..._0001`): When a pre-emptively restricted binary connects to a domain
/// and the operator applies `AllowPermanent` with a CIDR scope (`198.51.100.0/24`), the installed
/// `DomainPolicy` IP Permit preserves the known domain so adding a `NetworkBlock` rule for that
/// domain later immediately revokes the existing IP Permit.
#[tokio::test]
async fn daemon_p3_35_cidr_permanent_allow_revoked_when_domain_later_blocked() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let ps_exe = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    let ps_hash = "e".repeat(64);
    inspector.register(ps_exe, Some(&ps_hash), None);

    let pipe_name = unique_test_pipe_name();
    let engine = start_test_engine(
        store.clone(),
        DaemonConfig {
            pipe_name: pipe_name.clone(),
            dev_mode_bypass_ui_auth: true,
            preemptive_startup_executables: vec![ps_exe.to_string()],
            ..DaemonConfig::default()
        },
        defense.clone(),
        notifier,
        inspector,
    );
    let server = start_ipc_server(Arc::clone(&engine)).expect("start ipc");

    let now_ms = current_unix_ms();
    let proc_id = ProcessIdentity::new(8701, unix_ms_to_filetime(now_ms - 500));
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
    assert!(wait_until(1_000, || engine.active_process_table_len() == 1).await);

    let target_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42));
    engine
        .sender()
        .send(SensorEvent::DnsQuery {
            pid: proc_id.pid,
            query_name: "evil-later.example".to_string(),
            query_type: 1,
            resolved_ips: vec![target_ip],
            timestamp_ms: now_ms + 1,
        })
        .await
        .expect("send dns");
    engine
        .sender()
        .send(SensorEvent::NetworkConnect {
            pid: proc_id.pid,
            protocol: 6,
            dst_ip: target_ip,
            dst_port: 443,
            domain_hint: Some("evil-later.example".to_string()),
            timestamp_ms: now_ms + 2,
        })
        .await
        .expect("send connect");

    assert!(
        wait_until(1_500, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 10)
                .map(|a| a.len() == 1)
                .unwrap_or(false)
        })
        .await,
        "preemptive connect must emit pending alert"
    );
    let al = store.list_alerts(Some(AlertStatus::Pending), 10).unwrap()[0].clone();

    engine
        .resolve_alert(
            &al.alert_id,
            AlertDecision::AllowPermanent {
                use_signer_if_available: false,
                allow_dest: Some("198.51.100.0/24".to_string()),
            },
        )
        .expect("AllowPermanent CIDR succeeds");
    assert!(
        engine.has_active_wfp_filter(ps_exe, Some(target_ip), true),
        "CIDR AllowPermanent under preemptive app block must install IP permit for 198.51.100.42"
    );

    // Later operator blocks `evil-later.example` via IPC UpsertRule -> existing IP permit must
    // be revoked immediately on WFP reconciliation.
    let block_rule = make_net_rule(
        "R-LATER-DOMAIN-BLOCK",
        RuleScope::NetworkBlock,
        ps_exe,
        None,
        Some("evil-later.example"),
        now_ms + 50,
        "test",
    );
    let resp = send_ipc_async(&pipe_name, IpcRequest::UpsertRule { rule: block_rule }).await;
    assert!(matches!(resp, IpcResponse::Ack { .. }));
    assert!(
        !engine.has_active_wfp_filter(ps_exe, Some(target_ip), true),
        "existing CIDR-derived IP permit for 198.51.100.42 must be revoked when evil-later.example is blocked"
    );

    drop(server);
    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P3-36` (`BUG_..._0001`): A persistent WFP failure on an existing app-wide `NetworkAllow`
/// rule for `tool.exe` must NOT reject adding an independent domain `NetworkBlock` rule on the
/// SAME `tool.exe`, while re-upserting the failing `NetworkAllow` rule itself still fails with
/// `WFP_SYNC_ERROR`.
#[tokio::test]
async fn daemon_p3_36_same_exe_unrelated_app_allow_failure_allows_domain_block_save() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let tool_exe = r"C:\Tools\same_exe_tool.exe";
    let tool_hash = "9".repeat(64);
    inspector.register(tool_exe, Some(&tool_hash), None);
    defense.add_fail_wfp_exe("same_exe_tool.exe");

    let now_ms = current_unix_ms();
    let failing_app_allow = AllowlistRuleRecord {
        rule_id: "R-TOOL-APP-ALLOW".to_string(),
        scope: RuleScope::NetworkAllow,
        exe_path_pattern: tool_exe.to_string(),
        sha256: Some(tool_hash),
        signer_subject: None,
        root_thumbprint: None,
        allowed_target: None,
        created_at_ms: now_ms,
        created_by: "seed".to_string(),
    };
    store
        .upsert_rule(&failing_app_allow)
        .expect("seed failing app allow");

    let pipe_name = unique_test_pipe_name();
    let engine = start_test_engine(
        store.clone(),
        DaemonConfig {
            pipe_name: pipe_name.clone(),
            dev_mode_bypass_ui_auth: true,
            ..DaemonConfig::default()
        },
        defense,
        notifier,
        inspector,
    );
    let server = start_ipc_server(Arc::clone(&engine)).expect("start ipc");

    // 1. Adding an independent domain NetworkBlock on the SAME exe must succeed (`Ack`).
    let ads_block = make_net_rule(
        "R-TOOL-ADS-BLOCK",
        RuleScope::NetworkBlock,
        tool_exe,
        None,
        Some("ads.example.com"),
        now_ms + 10,
        "ui",
    );
    let resp_dom = send_ipc_async(&pipe_name, IpcRequest::UpsertRule { rule: ads_block }).await;
    assert!(
        matches!(resp_dom, IpcResponse::Ack { .. }),
        "independent domain block on same exe must succeed despite failing app-wide allow, got {resp_dom:?}"
    );
    assert!(store.get_rule("R-TOOL-ADS-BLOCK").unwrap().is_some());

    // 2. Re-upserting the failing app-wide NetworkAllow itself must still return `WFP_SYNC_ERROR`.
    let mut updated_app_allow = failing_app_allow;
    updated_app_allow.created_by = "ui-retry".to_string();
    let resp_allow = send_ipc_async(
        &pipe_name,
        IpcRequest::UpsertRule {
            rule: updated_app_allow,
        },
    )
    .await;
    assert!(
        matches!(&resp_allow, IpcResponse::Error { code, .. } if code == "WFP_SYNC_ERROR"),
        "re-upserting failing app-wide allow itself must return WFP_SYNC_ERROR, got {resp_allow:?}"
    );
    assert_eq!(
        store
            .get_rule("R-TOOL-APP-ALLOW")
            .unwrap()
            .unwrap()
            .created_by,
        "seed"
    );

    drop(server);
    engine.shutdown_and_flush().await.expect("shutdown");
}

struct GateBinaryInspector {
    target_substr: String,
    entered: Arc<AtomicBool>,
    release: Arc<AtomicBool>,
    wait_cap: Duration,
}

impl BinaryInspector for GateBinaryInspector {
    fn inspect(&self, exe_path: &str) -> BinaryIdentity {
        if exe_path.to_ascii_lowercase().contains(&self.target_substr) {
            let wait_loop = || {
                self.entered.store(true, Ordering::Release);
                let deadline = Instant::now() + self.wait_cap;
                while !self.release.load(Ordering::Acquire) && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(5));
                }
            };
            // Hand off the Tokio worker core before blocking in `std::thread::sleep` so the
            // multi-threaded runtime's timer driver is never starved by this test gate.
            if tokio::runtime::Handle::try_current()
                .is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
            {
                tokio::task::block_in_place(wait_loop);
            } else {
                wait_loop();
            }
        }
        BinaryIdentity {
            exe_path: exe_path.to_string(),
            sha256: Some("f".repeat(64)),
            authenticode: None,
        }
    }
}

/// `DAEMON-P3-37` (`BUG_..._0001`): `shutdown_and_flush` grants the worker task the full
/// `shutdown_flush_timeout_ms` budget (draining events that finish past `total_budget - 200ms`
/// without silent loss), and returns an error after best-effort checkpointing when draining
/// genuinely exceeds the budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_p3_37_shutdown_uses_full_drain_budget_and_reports_timeout_error() {
    // Part A: Drain completes at ~650ms (past the old `800 - 200 = 600ms` cutoff, within 800ms).
    {
        let store = LedrStore::open_in_memory().expect("open store");
        let defense = Arc::new(MockWfpDefense::new());
        let notifier = Arc::new(MockNotifier::default());
        let entered = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let inspector = Arc::new(GateBinaryInspector {
            target_substr: "slow_gate.exe".to_string(),
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
            wait_cap: Duration::from_secs(3),
        });

        let engine = Arc::new(start_test_engine(
            store.clone(),
            DaemonConfig {
                pipe_name: unique_test_pipe_name(),
                shutdown_flush_timeout_ms: 800,
                batch_flush_interval_ms: 500,
                ..DaemonConfig::default()
            },
            defense,
            notifier,
            inspector,
        ));

        let now_ms = current_unix_ms();
        let gate_proc = ProcessIdentity::new(8001, unix_ms_to_filetime(now_ms - 1_000));
        let trailing_proc = ProcessIdentity::new(8002, unix_ms_to_filetime(now_ms - 500));
        let trailing_id = format!("{}:{}", trailing_proc.pid, trailing_proc.create_time_100ns);

        engine
            .sender()
            .send(SensorEvent::ProcessStart {
                identity: gate_proc,
                parent_pid: 4,
                exe_path: r"C:\Tools\slow_gate.exe".to_string(),
                command_line: r"C:\Tools\slow_gate.exe".to_string(),
                user_sid: None,
            })
            .await
            .expect("send slow_gate start");
        assert!(wait_until(1_000, || engine.active_process_table_len() == 1).await);

        // External NetworkConnect triggers GateBinaryInspector::inspect on the worker task.
        engine
            .sender()
            .send(SensorEvent::NetworkConnect {
                pid: gate_proc.pid,
                protocol: 6,
                dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
                dst_port: 443,
                domain_hint: None,
                timestamp_ms: now_ms,
            })
            .await
            .expect("send slow_gate connect");
        assert!(
            wait_until(1_000, || entered.load(Ordering::Acquire)).await,
            "worker must enter slow_gate inspect"
        );

        // Enqueue trailing ProcessStart while worker is blocked in inspect, then call shutdown.
        engine
            .sender()
            .send(SensorEvent::ProcessStart {
                identity: trailing_proc,
                parent_pid: 4,
                exe_path: r"C:\Tools\trailing_drained.exe".to_string(),
                command_line: r"C:\Tools\trailing_drained.exe".to_string(),
                user_sid: None,
            })
            .await
            .expect("send trailing start");

        let engine_c = Arc::clone(&engine);
        let shutdown_task = tokio::spawn(async move { engine_c.shutdown_and_flush().await });
        tokio::time::sleep(Duration::from_millis(650)).await;
        release.store(true, Ordering::Release);

        let shutdown_res = shutdown_task.await.expect("join shutdown task");
        assert!(
            shutdown_res.is_ok(),
            "drain finishing at 650ms inside 800ms budget must succeed: {shutdown_res:?}"
        );
        let persisted = store
            .list_running_process_instance_ids()
            .expect("list running processes");
        assert!(
            persisted.contains(&trailing_id),
            "trailing queued ProcessStart ({trailing_id}) must survive full-budget drain: {persisted:?}"
        );
    }

    // Part B: Drain genuinely exceeding `shutdown_flush_timeout_ms` returns Err after checkpoint.
    {
        let store = LedrStore::open_in_memory().expect("open store");
        let defense = Arc::new(MockWfpDefense::new());
        let notifier = Arc::new(MockNotifier::default());
        let entered = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let inspector = Arc::new(GateBinaryInspector {
            target_substr: "slow_gate.exe".to_string(),
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
            wait_cap: Duration::from_secs(2),
        });

        let engine = start_test_engine(
            store.clone(),
            DaemonConfig {
                pipe_name: unique_test_pipe_name(),
                shutdown_flush_timeout_ms: 150,
                batch_flush_interval_ms: 500,
                ..DaemonConfig::default()
            },
            defense,
            notifier,
            inspector,
        );

        let now_ms = current_unix_ms();
        let gate_proc = ProcessIdentity::new(8101, unix_ms_to_filetime(now_ms - 1_000));
        engine
            .sender()
            .send(SensorEvent::ProcessStart {
                identity: gate_proc,
                parent_pid: 4,
                exe_path: r"C:\Tools\slow_gate.exe".to_string(),
                command_line: r"C:\Tools\slow_gate.exe".to_string(),
                user_sid: None,
            })
            .await
            .expect("send slow_gate start");
        assert!(wait_until(1_000, || engine.active_process_table_len() == 1).await);

        engine
            .sender()
            .send(SensorEvent::NetworkConnect {
                pid: gate_proc.pid,
                protocol: 6,
                dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
                dst_port: 443,
                domain_hint: None,
                timestamp_ms: now_ms,
            })
            .await
            .expect("send slow_gate connect");
        assert!(wait_until(1_000, || entered.load(Ordering::Acquire)).await);

        let err = engine
            .shutdown_and_flush()
            .await
            .expect_err("over-budget drain timeout must return Err");
        assert!(
            err.to_string().to_ascii_lowercase().contains("timeout"),
            "timeout error must be descriptive, got: {err}"
        );
        // Best-effort checkpoint kept store operational.
        assert!(store.list_running_process_instance_ids().is_ok());
        release.store(true, Ordering::Release);
    }
}

/// `DAEMON-P3-38` (`BUG_..._0002` / `PRRT_..._W1_R`): Deleting or narrowing a shadowing
/// `NetworkBlock` rule uncovers an underlying `NetworkAllow`; if adding that uncovered Permit
/// fails, the delete/edit must roll back SQLite + WFP Block and return `FirewallSync`, while
/// editing unrelated rules on the same exe when another allow already failed still succeeds.
#[tokio::test]
async fn daemon_p3_38_shadowing_block_delete_or_narrow_rolls_back_on_permit_restore_failure() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let exe = r"C:\Tools\shadow_test.exe";
    let sha = "a".repeat(64);
    inspector.register(exe, Some(&sha), None);
    let ip_shadowed = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
    let ip_other = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
    let now_ms = current_unix_ms();

    store
        .upsert_rule(&AllowlistRuleRecord {
            rule_id: "R-ALLOW-198".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: exe.to_string(),
            sha256: Some(sha.clone()),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("198.51.100.10".to_string()),
            created_at_ms: now_ms,
            created_by: "seed".to_string(),
        })
        .expect("seed allow 198");
    store
        .upsert_rule(&AllowlistRuleRecord {
            rule_id: "R-BLOCK-198".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: exe.to_string(),
            sha256: Some(sha.clone()),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("198.51.100.10".to_string()),
            created_at_ms: now_ms + 1,
            created_by: "seed".to_string(),
        })
        .expect("seed block 198");
    // Pre-existing Permit failure on `ip_other` (unrelated to R-BLOCK-99 below).
    store
        .upsert_rule(&AllowlistRuleRecord {
            rule_id: "R-ALLOW-OTHER".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: exe.to_string(),
            sha256: Some(sha.clone()),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("203.0.113.5".to_string()),
            created_at_ms: now_ms + 2,
            created_by: "seed".to_string(),
        })
        .expect("seed allow other");
    store
        .upsert_rule(&AllowlistRuleRecord {
            rule_id: "R-BLOCK-99".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: exe.to_string(),
            sha256: Some(sha.clone()),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("203.0.113.99".to_string()),
            created_at_ms: now_ms + 3,
            created_by: "seed".to_string(),
        })
        .expect("seed unrelated block 99");

    // Permit adds fail from startup (`R-ALLOW-OTHER` is already unapplied; `R-BLOCK-198` &
    // `R-BLOCK-99` are Block filters so they install cleanly).
    defense.set_fail_wfp_add_permits(true);

    let engine = start_test_engine(
        store.clone(),
        default_test_config(),
        defense.clone(),
        notifier,
        inspector,
    );
    assert!(engine.has_active_wfp_filter(exe, Some(ip_shadowed), false));
    assert!(!engine.has_active_wfp_filter(exe, Some(ip_other), true));

    // 1. Deleting shadowing `R-BLOCK-198` uncovers `R-ALLOW-198` whose Permit add fails ->
    //    MUST fail with `FirewallSync` and roll back both SQLite + WFP Block!
    let del_err = engine
        .delete_policy_rule("R-BLOCK-198")
        .expect_err("delete shadowing block with failing uncovered permit must fail");
    assert!(
        matches!(del_err, PolicyRuleError::FirewallSync(_)),
        "expected FirewallSync, got {del_err:?}"
    );
    assert!(
        store.get_rule("R-BLOCK-198").unwrap().is_some(),
        "R-BLOCK-198 must be restored in SQLite after rollback"
    );
    assert!(
        engine.has_active_wfp_filter(exe, Some(ip_shadowed), false),
        "WFP Block on 198.51.100.10 must be restored after rollback"
    );

    // 2. Narrowing `R-BLOCK-198` to 198.51.100.99 also uncovers `R-ALLOW-198` ->
    //    MUST fail with `FirewallSync` and restore old target + WFP Block!
    let narrowed = AllowlistRuleRecord {
        rule_id: "R-BLOCK-198".to_string(),
        scope: RuleScope::NetworkBlock,
        exe_path_pattern: exe.to_string(),
        sha256: Some(sha),
        signer_subject: None,
        root_thumbprint: None,
        allowed_target: Some("198.51.100.99".to_string()),
        created_at_ms: now_ms + 10,
        created_by: "ui".to_string(),
    };
    let narrow_err = engine
        .upsert_policy_rule(&narrowed)
        .expect_err("narrowing shadowing block with failing uncovered permit must fail");
    assert!(matches!(narrow_err, PolicyRuleError::FirewallSync(_)));
    assert_eq!(
        store
            .get_rule("R-BLOCK-198")
            .unwrap()
            .unwrap()
            .allowed_target
            .as_deref(),
        Some("198.51.100.10")
    );
    assert!(engine.has_active_wfp_filter(exe, Some(ip_shadowed), false));

    // 3. Negative control: deleting unrelated `R-BLOCK-99` does NOT newly uncover `R-ALLOW-OTHER`
    //    (its Permit failure was pre-existing), so deleting `R-BLOCK-99` MUST succeed!
    engine.delete_policy_rule("R-BLOCK-99").expect(
        "deleting unrelated block despite pre-existing unrelated permit failure must succeed",
    );
    assert!(store.get_rule("R-BLOCK-99").unwrap().is_none());

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P3-39` (`BUG_..._0003`): Retired DNS history (domain moved to a new IP or >60s old
/// on ambiguous multi-instance drops) must not continue blocking a CIDR-allowed IP or pin a
/// sticky `DomainPolicy` IP Block filter.
#[tokio::test]
async fn daemon_p3_39_rotated_or_stale_dns_history_stops_blocking_cidr_allowed_ip() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let exe = r"C:\Tools\cidr_dns_app.exe";
    let sha = "b".repeat(64);
    inspector.register(exe, Some(&sha), None);
    let now_ms = current_unix_ms();

    store
        .upsert_rule(&AllowlistRuleRecord {
            rule_id: "R-CIDR-ALLOW".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: exe.to_string(),
            sha256: Some(sha.clone()),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("198.51.100.0/24".to_string()),
            created_at_ms: now_ms,
            created_by: "seed".to_string(),
        })
        .expect("seed cidr allow");
    store
        .upsert_rule(&AllowlistRuleRecord {
            rule_id: "R-DOM-BLOCK-EVIL".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: exe.to_string(),
            sha256: Some(sha.clone()),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("evil.example".to_string()),
            created_at_ms: now_ms + 1,
            created_by: "seed".to_string(),
        })
        .expect("seed evil block");

    let engine = start_test_engine(
        store.clone(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            preemptive_startup_executables: vec![exe.to_string()],
            wfp_drop_dns_grace_ms: 40,
            ..DaemonConfig::default()
        },
        defense,
        notifier,
        inspector,
    );

    let p1 = ProcessIdentity::new(9101, unix_ms_to_filetime(now_ms - 500));
    let p2 = ProcessIdentity::new(9102, unix_ms_to_filetime(now_ms - 400));
    for proc_id in [p1, p2] {
        engine
            .sender()
            .send(SensorEvent::ProcessStart {
                identity: proc_id,
                parent_pid: 4,
                exe_path: exe.to_string(),
                command_line: exe.to_string(),
                user_sid: None,
            })
            .await
            .expect("start proc");
    }
    assert!(wait_until(1_000, || engine.active_process_table_len() == 2).await);

    // Part A: `evil.example` first resolves to `198.51.100.50` (inside allowed CIDR), then
    // migrates to `203.0.113.77`. The old `DomainPolicy` Block and DNS history for `.50` must
    // be invalidated so reconnects to `.50` are allowed by CIDR.
    let old_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 50));
    let new_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77));
    engine
        .sender()
        .send(SensorEvent::DnsQuery {
            pid: p1.pid,
            query_name: "evil.example".to_string(),
            query_type: 1,
            resolved_ips: vec![old_ip],
            timestamp_ms: now_ms + 10,
        })
        .await
        .expect("evil dns old ip");
    assert!(
        wait_until(1_000, || engine.has_active_wfp_filter(
            exe,
            Some(old_ip),
            false
        ))
        .await,
        "initial evil.example DnsQuery must materialize DomainPolicy Block on old_ip"
    );

    engine
        .sender()
        .send(SensorEvent::DnsQuery {
            pid: p1.pid,
            query_name: "evil.example".to_string(),
            query_type: 1,
            resolved_ips: vec![new_ip],
            timestamp_ms: now_ms + 20,
        })
        .await
        .expect("evil dns new ip");
    assert!(
        wait_until(1_000, || {
            engine.has_active_wfp_filter(exe, Some(new_ip), false)
                && !engine.has_active_wfp_filter(exe, Some(old_ip), false)
        })
        .await,
        "evil.example migration must add DomainPolicy Block on new_ip and remove stale Block on old_ip"
    );

    assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
        os_filter_id: 1,
        rule_handle: 1,
        exe_path: exe.to_string(),
        protocol: 6,
        dst_ip: old_ip,
        dst_port: 443,
        timestamp_ms: now_ms + 30,
    }));
    assert!(
        wait_until(1_000, || engine.has_active_wfp_filter(
            exe,
            Some(old_ip),
            true
        ))
        .await,
        "CIDR allow must materialize Permit for retired old_ip"
    );
    assert!(store.list_alerts(None, 20).unwrap().is_empty());

    // Part B: Ambiguous drop with fresh (<60s) DNS for a blocked domain alerts under the app
    // block WITHOUT minting a sticky `DomainPolicy` Block filter; once >60s old, CIDR allow wins.
    let shared_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 60));
    assert!(
        wait_until(1_000, || engine.metrics().telemetry_processed >= 2).await,
        "Part A telemetry DNS queries must finish before Part B barrier baseline"
    );
    let before_telemetry = engine.metrics().telemetry_processed;
    engine
        .sender()
        .send(SensorEvent::DnsQuery {
            pid: p2.pid,
            query_name: "stale-trap.example".to_string(),
            query_type: 1,
            resolved_ips: vec![shared_ip],
            timestamp_ms: now_ms + 40,
        })
        .await
        .expect("dns before block rule");
    assert!(
        wait_until(1_000, || {
            engine.metrics().telemetry_processed > before_telemetry
        })
        .await,
        "stale-trap.example DnsQuery on Telemetry lane must finish before adding block rule"
    );

    engine
        .upsert_policy_rule(&AllowlistRuleRecord {
            rule_id: "R-DOM-BLOCK-STALE".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: exe.to_string(),
            sha256: Some(sha),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("stale-trap.example".to_string()),
            created_at_ms: now_ms + 50,
            created_by: "ui".to_string(),
        })
        .expect("add stale-trap block");

    assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
        os_filter_id: 2,
        rule_handle: 2,
        exe_path: exe.to_string(),
        protocol: 6,
        dst_ip: shared_ip,
        dst_port: 443,
        timestamp_ms: now_ms + 5_000,
    }));
    assert!(
        wait_until(1_000, || {
            store
                .list_alerts(None, 20)
                .unwrap()
                .iter()
                .any(|a| a.rule_id == "LEDR-NET-POLICY-BLOCK")
        })
        .await,
        "fresh ambiguous DNS drop must emit LEDR-NET-POLICY-BLOCK"
    );
    assert!(
        !engine.has_active_wfp_filter(exe, Some(shared_ip), false),
        "ambiguous DNS correlation must not pin a sticky DomainPolicy IP Block under active_app_block"
    );

    // Once DNS entry exceeds the 60s freshness window, ambiguous drop falls back cleanly to CIDR allow.
    assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
        os_filter_id: 3,
        rule_handle: 3,
        exe_path: exe.to_string(),
        protocol: 6,
        dst_ip: shared_ip,
        dst_port: 443,
        timestamp_ms: now_ms + 70_000,
    }));
    assert!(
        wait_until(1_000, || engine.has_active_wfp_filter(
            exe,
            Some(shared_ip),
            true
        ))
        .await,
        "after >60s stale DNS expiry, CIDR allow must permit shared_ip"
    );

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P3-40` (`BUG_..._0004`): A failing `remove_domain_policy_permit` caused by an existing
/// block on `evil.example` must be attributed to `evil.example`'s blocking rule(s) rather than
/// blocking edits/saves of unrelated domain rules (`good.example`) on the same executable.
#[tokio::test]
async fn daemon_p3_40_unrelated_domain_permit_removal_failure_scoped_away_from_good_domain() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let exe = r"C:\Tools\multi_dom.exe";
    let sha = "c".repeat(64);
    inspector.register(exe, Some(&sha), None);
    let now_ms = current_unix_ms();

    let evil_rule = AllowlistRuleRecord {
        rule_id: "R-BLK-EVIL".to_string(),
        scope: RuleScope::NetworkBlock,
        exe_path_pattern: exe.to_string(),
        sha256: Some(sha.clone()),
        signer_subject: None,
        root_thumbprint: None,
        allowed_target: Some("evil.example".to_string()),
        created_at_ms: now_ms,
        created_by: "seed".to_string(),
    };
    store
        .upsert_rule(&AllowlistRuleRecord {
            rule_id: "R-CIDR-ALLOW".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: exe.to_string(),
            sha256: Some(sha.clone()),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("198.51.100.0/24".to_string()),
            created_at_ms: now_ms + 1,
            created_by: "seed".to_string(),
        })
        .expect("seed cidr allow");
    store.upsert_rule(&evil_rule).expect("seed evil block");

    let engine = start_test_engine(
        store.clone(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            preemptive_startup_executables: vec![exe.to_string()],
            wfp_drop_dns_grace_ms: 40,
            ..DaemonConfig::default()
        },
        defense.clone(),
        notifier,
        inspector,
    );

    let p1 = ProcessIdentity::new(9201, unix_ms_to_filetime(now_ms - 500));
    let p2 = ProcessIdentity::new(9202, unix_ms_to_filetime(now_ms - 400));
    for proc_id in [p1, p2] {
        engine
            .sender()
            .send(SensorEvent::ProcessStart {
                identity: proc_id,
                parent_pid: 4,
                exe_path: exe.to_string(),
                command_line: exe.to_string(),
                user_sid: None,
            })
            .await
            .expect("start proc");
    }
    assert!(wait_until(1_000, || engine.active_process_table_len() == 2).await);

    // Ambiguous CIDR drop before DNS creates an unnamed (`domain_hint: ""`) Permit for `ip`.
    let shared_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 88));
    assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
        os_filter_id: 1,
        rule_handle: 1,
        exe_path: exe.to_string(),
        protocol: 6,
        dst_ip: shared_ip,
        dst_port: 443,
        timestamp_ms: now_ms + 10,
    }));
    assert!(
        wait_until(1_000, || {
            engine.has_active_wfp_filter(exe, Some(shared_ip), true)
        })
        .await
    );

    let permit_handle = defense
        .active_wfp()
        .into_iter()
        .find(|w| w.allow && w.remote_ip == Some(shared_ip))
        .expect("live IP permit filter")
        .handle;
    defense.add_fail_wfp_remove_handle(permit_handle);

    // Associate `shared_ip` with blocked `evil.example` in DNS history and synchronize on the
    // Telemetry lane completion counter rather than a cross-lane HighPriority `ProcessStart`.
    let before_telemetry = engine.metrics().telemetry_processed;
    engine
        .sender()
        .send(SensorEvent::DnsQuery {
            pid: p1.pid,
            query_name: "evil.example".to_string(),
            query_type: 1,
            resolved_ips: vec![shared_ip],
            timestamp_ms: now_ms + 20,
        })
        .await
        .expect("send evil dns");
    assert!(
        wait_until(1_000, || {
            engine.metrics().telemetry_processed > before_telemetry
        })
        .await,
        "evil.example DnsQuery on Telemetry lane must finish before policy rule mutations"
    );

    // 1. Saving an unrelated domain rule (`good.example`) on the SAME exe MUST succeed despite
    //    `remove_domain_policy_permit` failing for `evil.example`'s IP permit.
    engine
        .upsert_policy_rule(&AllowlistRuleRecord {
            rule_id: "R-GOOD-ALLOW".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: exe.to_string(),
            sha256: Some(sha),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("good.example".to_string()),
            created_at_ms: now_ms + 30,
            created_by: "ui".to_string(),
        })
        .expect("saving unrelated good.example rule must succeed");
    assert!(store.get_rule("R-GOOD-ALLOW").unwrap().is_some());

    // 2. Re-upserting `R-BLK-EVIL` (`evil.example`) itself MUST fail with `FirewallSync` and roll back.
    let mut updated_evil = evil_rule;
    updated_evil.created_by = "ui-retry".to_string();
    let evil_err = engine
        .upsert_policy_rule(&updated_evil)
        .expect_err("touching evil.example rule whose permit removal failed must fail");
    assert!(matches!(evil_err, PolicyRuleError::FirewallSync(_)));
    assert_eq!(
        store.get_rule("R-BLK-EVIL").unwrap().unwrap().created_by,
        "seed"
    );

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P3-41` (`SEC_..._0001` / `PRRT_..._W2BQ`): When an app-wide `NetworkBlock` fails to
/// apply in WFP, adding a destination-specific literal-IP `NetworkBlock` subsumed under that app
/// rule must not silently return success — it must roll back SQLite and report `FirewallSync`.
#[tokio::test]
async fn daemon_p3_41_unapplied_app_block_surfaces_failure_for_subsumed_ip_block() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let exe = r"C:\Tools\broken_app_block.exe";
    let sha = "d".repeat(64);
    inspector.register(exe, Some(&sha), None);
    let now_ms = current_unix_ms();

    store
        .upsert_rule(&AllowlistRuleRecord {
            rule_id: "R-APP-BLK".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: exe.to_string(),
            sha256: Some(sha.clone()),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: None,
            created_at_ms: now_ms,
            created_by: "seed".to_string(),
        })
        .expect("seed app-wide block");
    defense.add_fail_wfp_exe("broken_app_block.exe");

    let engine = start_test_engine(
        store.clone(),
        default_test_config(),
        defense.clone(),
        notifier,
        inspector,
    );
    assert!(
        !engine.has_active_wfp_filter(exe, None, false),
        "app-wide WFP block must be unapplied at startup due to injected exe failure"
    );

    let err = engine
        .upsert_policy_rule(&AllowlistRuleRecord {
            rule_id: "R-IP-BLK".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: exe.to_string(),
            sha256: Some(sha),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("203.0.113.44".to_string()),
            created_at_ms: now_ms + 10,
            created_by: "ui".to_string(),
        })
        .expect_err("saving literal-IP block hidden under failing app-wide block must fail");
    assert!(
        matches!(err, PolicyRuleError::FirewallSync(_)),
        "expected FirewallSync, got {err:?}"
    );
    assert!(
        store.get_rule("R-IP-BLK").unwrap().is_none(),
        "R-IP-BLK must be rolled back from SQLite when neither app-wide nor IP block is live"
    );

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P3-42` (`BUG_..._0003` edge cases):
/// 1. Two blocked domains sharing one IP keep it blocked while either still resolves there, and
///    release the stale `DomainPolicy` Block filter once both domains have migrated away.
/// 2. IPv4-only DNS rotation preserves an existing IPv6 `DomainPolicy` Block filter even after the
///    original querying process exited.
/// 3. An out-of-order older-timestamp `DnsQuery` (both direct Telemetry lane and domain-rule
///    promoted HighPriority lane via `classified_sender()`) does not re-materialize a retired IP Block.
#[tokio::test]
async fn daemon_p3_42_shared_ip_dual_stack_and_out_of_order_dns_block_invalidation() {
    use std::net::Ipv6Addr;

    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let exe = r"C:\Tools\dns_edge.exe";
    let sha = "e".repeat(64);
    inspector.register(exe, Some(&sha), None);
    let now_ms = current_unix_ms();

    for (rid, dom) in [("R-BLK-1", "one.example"), ("R-BLK-2", "two.example")] {
        store
            .upsert_rule(&AllowlistRuleRecord {
                rule_id: rid.to_string(),
                scope: RuleScope::NetworkBlock,
                exe_path_pattern: exe.to_string(),
                sha256: Some(sha.clone()),
                signer_subject: None,
                root_thumbprint: None,
                allowed_target: Some(dom.to_string()),
                created_at_ms: now_ms,
                created_by: "seed".to_string(),
            })
            .expect("seed domain block");
    }

    let engine = start_test_engine(
        store.clone(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            preemptive_startup_executables: vec![exe.to_string()],
            ..DaemonConfig::default()
        },
        defense,
        notifier,
        inspector,
    );

    let p1 = ProcessIdentity::new(9301, unix_ms_to_filetime(now_ms - 500));
    let p2 = ProcessIdentity::new(9302, unix_ms_to_filetime(now_ms - 400));
    for proc_id in [p1, p2] {
        engine
            .sender()
            .send(SensorEvent::ProcessStart {
                identity: proc_id,
                parent_pid: 4,
                exe_path: exe.to_string(),
                command_line: exe.to_string(),
                user_sid: None,
            })
            .await
            .expect("start proc");
    }
    assert!(wait_until(1_000, || engine.active_process_table_len() == 2).await);

    let shared_v4 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 120));
    let v4_one_new = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 121));
    let v4_two_new = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 122));
    let v6_one = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x55));

    // Both `one.example` and `two.example` resolve to `shared_v4`, and `one.example` also has `v6_one`.
    engine
        .sender()
        .send(SensorEvent::DnsQuery {
            pid: p1.pid,
            query_name: "one.example".to_string(),
            query_type: 1,
            resolved_ips: vec![shared_v4],
            timestamp_ms: now_ms + 10,
        })
        .await
        .expect("one v4");
    engine
        .sender()
        .send(SensorEvent::DnsQuery {
            pid: p1.pid,
            query_name: "one.example".to_string(),
            query_type: 28,
            resolved_ips: vec![v6_one],
            timestamp_ms: now_ms + 15,
        })
        .await
        .expect("one v6");
    engine
        .sender()
        .send(SensorEvent::DnsQuery {
            pid: p2.pid,
            query_name: "two.example".to_string(),
            query_type: 1,
            resolved_ips: vec![shared_v4],
            timestamp_ms: now_ms + 20,
        })
        .await
        .expect("two v4");
    assert!(
        wait_until(1_000, || {
            engine.has_active_wfp_filter(exe, Some(shared_v4), false)
                && engine.has_active_wfp_filter(exe, Some(v6_one), false)
        })
        .await
    );

    // `p1` exits (evicting `p1`'s `v6_one` entry from ProcessDnsHistory), then `p2` moves
    // `one.example` IPv4 to `v4_one_new`: `shared_v4` stays blocked for `two.example` and
    // `v6_one` stays blocked for IPv6!
    engine
        .sender()
        .send(SensorEvent::ProcessStop {
            pid: p1.pid,
            exit_time_100ns: unix_ms_to_filetime(now_ms + 25),
            exit_code: 0,
        })
        .await
        .expect("stop p1");
    engine
        .sender()
        .send(SensorEvent::DnsQuery {
            pid: p2.pid,
            query_name: "one.example".to_string(),
            query_type: 1,
            resolved_ips: vec![v4_one_new],
            timestamp_ms: now_ms + 30,
        })
        .await
        .expect("one v4 move");
    assert!(
        wait_until(1_000, || engine.has_active_wfp_filter(
            exe,
            Some(v4_one_new),
            false
        ))
        .await
    );
    assert!(
        engine.has_active_wfp_filter(exe, Some(shared_v4), false),
        "shared_v4 must stay blocked while two.example still points there"
    );
    assert!(
        engine.has_active_wfp_filter(exe, Some(v6_one), false),
        "IPv4-only move of one.example must preserve IPv6 DomainPolicy Block"
    );

    // Now `two.example` also moves off `shared_v4` -> `shared_v4` Block (originally tagged with
    // `domain_hint: "one.example"`) MUST be invalidated!
    engine
        .sender()
        .send(SensorEvent::DnsQuery {
            pid: p2.pid,
            query_name: "two.example".to_string(),
            query_type: 1,
            resolved_ips: vec![v4_two_new],
            timestamp_ms: now_ms + 40,
        })
        .await
        .expect("two v4 move");
    assert!(
        wait_until(1_000, || {
            engine.has_active_wfp_filter(exe, Some(v4_two_new), false)
                && !engine.has_active_wfp_filter(exe, Some(shared_v4), false)
        })
        .await,
        "shared_v4 block must be removed once both domains migrated away"
    );

    // Synchronize all 5 prior Telemetry `DnsQuery` events (`one v4`, `one v6`, `two v4`,
    // `one v4 move`, `two v4 move`) so `telemetry_processed` reflects a clean baseline before
    // sending the delayed out-of-order query.
    assert!(
        wait_until(1_000, || engine.metrics().telemetry_processed >= 5).await,
        "all 5 prior Telemetry DnsQuery events must complete before baseline snapshot"
    );

    // Delayed out-of-order query for `two.example` -> `shared_v4` with an older timestamp (`now_ms + 5`)
    // on the Telemetry lane must NOT re-install the retired Block filter.
    let before_telemetry = engine.metrics().telemetry_processed;
    engine
        .sender()
        .send(SensorEvent::DnsQuery {
            pid: p2.pid,
            query_name: "two.example".to_string(),
            query_type: 1,
            resolved_ips: vec![shared_v4],
            timestamp_ms: now_ms + 5,
        })
        .await
        .expect("stale out-of-order dns (telemetry lane)");
    assert!(
        wait_until(1_000, || {
            engine.metrics().telemetry_processed > before_telemetry
        })
        .await,
        "delayed out-of-order DnsQuery on Telemetry lane must be processed"
    );
    assert!(
        !engine.has_active_wfp_filter(exe, Some(shared_v4), false),
        "out-of-order older DnsQuery (Telemetry lane) must not re-materialize retired shared_v4 Block"
    );

    // Production-equivalent path: with domain rules active, `classified_sender()` promotes
    // external `DnsQuery` onto the HighPriority lane (`L-10`). Synchronize prior HighPriority
    // events (`p1 start`, `p2 start`, `p1 stop`), verify promotion, wait for
    // `high_priority_processed` to increment, and confirm the retired Block filter is not re-created.
    assert!(
        wait_until(1_000, || engine.metrics().high_priority_processed >= 3).await,
        "prior HighPriority events (p1 start, p2 start, p1 stop) must complete before baseline"
    );
    let classified = engine.classified_sender();
    let promoted_stale_dns = SensorEvent::DnsQuery {
        pid: p2.pid,
        query_name: "two.example".to_string(),
        query_type: 1,
        resolved_ips: vec![shared_v4],
        timestamp_ms: now_ms + 6,
    };
    assert!(
        classified.should_promote(&promoted_stale_dns),
        "with domain rules active, external DnsQuery via classified_sender() must promote to HighPriority"
    );
    let before_hp = engine.metrics().high_priority_processed;
    classified
        .send(promoted_stale_dns)
        .await
        .expect("stale out-of-order dns (classified HighPriority lane)");
    assert!(
        wait_until(1_000, || {
            engine.metrics().high_priority_processed > before_hp
        })
        .await,
        "delayed out-of-order DnsQuery promoted via classified_sender() must be processed on HighPriority lane"
    );
    assert!(
        !engine.has_active_wfp_filter(exe, Some(shared_v4), false),
        "out-of-order older DnsQuery (HighPriority lane) must not re-materialize retired shared_v4 Block"
    );

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P3-43` (`R-07` / `R-03`, `L-03` / `L-10` / `AUTO-05`):
/// 1. Under a pre-emptively restricted single process with a domain-scoped `NetworkAllow` rule for
///    `good.example`, processing `A 198.51.100.10 (t=1000)` -> `AAAA 2001:db8::1 (t=3000)` ->
///    late-arriving `A 198.51.100.20 (t=2000)` tracks IPv4 and IPv6 independently so the newer
///    IPv4 `.20` materializes a WFP Permit (connecting produces zero suspends/alerts) while
///    preserving the IPv6 `2001:db8::1` Permit.
/// 2. A genuinely stale `A` response (`t=500`, older than the latest IPv4 `t=2000`) is rejected
///    and must neither materialize a Permit nor wake a parked `WfpDropEvent` early into a false
///    suspend/alert before the real fresh `A` response arrives within the grace window.
#[tokio::test]
async fn daemon_p3_43_dual_stack_out_of_order_dns_permit_and_stale_drop_rejection() {
    use std::net::Ipv6Addr;

    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let exe = r"C:\Temp\dual_stack_allow.exe";
    let sha = "a".repeat(64);
    inspector.register(exe, Some(&sha), None);

    let now_ms = current_unix_ms();
    let base_ts = now_ms - 4_000;

    store
        .upsert_rule(&AllowlistRuleRecord {
            rule_id: "R-ALLOW-GOOD-DUALSTACK".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: exe.to_string(),
            sha256: Some(sha),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("good.example".to_string()),
            created_at_ms: now_ms - 10_000,
            created_by: "seed".to_string(),
        })
        .expect("seed good.example allow rule");

    let engine = start_test_engine(
        store.clone(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            preemptive_startup_executables: vec![exe.to_string()],
            wfp_drop_dns_grace_ms: 600,
            ..DaemonConfig::default()
        },
        defense.clone(),
        notifier,
        inspector,
    );

    let p1 = ProcessIdentity::new(9401, unix_ms_to_filetime(now_ms - 10_000));
    engine
        .sender()
        .send(SensorEvent::ProcessStart {
            identity: p1,
            parent_pid: 4,
            exe_path: exe.to_string(),
            command_line: exe.to_string(),
            user_sid: None,
        })
        .await
        .expect("start single pre-restricted process");
    assert!(
        wait_until(1_000, || {
            engine.active_process_table_len() == 1 && engine.metrics().high_priority_processed >= 1
        })
        .await,
        "ProcessStart must complete before DNS sequence"
    );

    let classified = engine.classified_sender();
    let v4_t1000 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
    let v4_t2000 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20));
    let v6_t3000 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1));

    // Step 1: A 198.51.100.10 (t=1000)
    let dns_v4_10 = SensorEvent::DnsQuery {
        pid: p1.pid,
        query_name: "good.example".to_string(),
        query_type: 1,
        resolved_ips: vec![v4_t1000],
        timestamp_ms: base_ts + 1_000,
    };
    assert!(
        classified.should_promote(&dns_v4_10),
        "external DnsQuery with active domain rule must promote via classified_sender()"
    );
    let hp_before = engine.metrics().high_priority_processed;
    classified.send(dns_v4_10).await.expect("send A .10 t=1000");
    assert!(
        wait_until(1_000, || {
            engine.metrics().high_priority_processed > hp_before
                && engine.has_active_wfp_filter(exe, Some(v4_t1000), true)
        })
        .await,
        "A 198.51.100.10 (t=1000) must materialize WFP Permit"
    );

    // Step 2: AAAA 2001:db8::1 (t=3000)
    let hp_before = engine.metrics().high_priority_processed;
    classified
        .send(SensorEvent::DnsQuery {
            pid: p1.pid,
            query_name: "good.example".to_string(),
            query_type: 28,
            resolved_ips: vec![v6_t3000],
            timestamp_ms: base_ts + 3_000,
        })
        .await
        .expect("send AAAA 2001:db8::1 t=3000");
    assert!(
        wait_until(1_000, || {
            engine.metrics().high_priority_processed > hp_before
                && engine.has_active_wfp_filter(exe, Some(v6_t3000), true)
        })
        .await,
        "AAAA 2001:db8::1 (t=3000) must materialize IPv6 WFP Permit"
    );

    // Step 3: Late-arriving A 198.51.100.20 (t=2000) — older than AAAA (t=3000) but newer than
    // previous A (t=1000). Must be accepted per-family, materialize IPv4 `.20` Permit, and retain
    // IPv6 `2001:db8::1` Permit.
    let hp_before = engine.metrics().high_priority_processed;
    classified
        .send(SensorEvent::DnsQuery {
            pid: p1.pid,
            query_name: "good.example".to_string(),
            query_type: 1,
            resolved_ips: vec![v4_t2000],
            timestamp_ms: base_ts + 2_000,
        })
        .await
        .expect("send late A .20 t=2000");
    assert!(
        wait_until(1_000, || engine.metrics().high_priority_processed
            > hp_before)
        .await,
        "late A 198.51.100.20 (t=2000) must be processed"
    );
    assert!(
        engine.has_active_wfp_filter(exe, Some(v4_t2000), true),
        "late-arriving A 198.51.100.20 (t=2000) must materialize WFP Permit despite newer AAAA (t=3000)"
    );
    assert!(
        engine.has_active_wfp_filter(exe, Some(v6_t3000), true),
        "IPv4 A update must preserve existing IPv6 2001:db8::1 WFP Permit"
    );

    // Connecting to both `.20` and `2001:db8::1` with `domain_hint: None` (resolved solely from
    // ProcessDnsHistory) must be allowed with zero suspends and zero alerts.
    for (dst_ip, ts_off) in [(v4_t2000, 3_100), (v6_t3000, 3_200)] {
        let conn = SensorEvent::NetworkConnect {
            pid: p1.pid,
            protocol: 6,
            dst_ip,
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: base_ts + ts_off,
        };
        let promoted = classified.should_promote(&conn);
        let before_hp = engine.metrics().high_priority_processed;
        let before_tel = engine.metrics().telemetry_processed;
        classified.send(conn).await.expect("send allowed connect");
        assert!(
            wait_until(1_000, || {
                if promoted {
                    engine.metrics().high_priority_processed > before_hp
                } else {
                    engine.metrics().telemetry_processed > before_tel
                }
            })
            .await,
            "NetworkConnect to {dst_ip} must be processed"
        );
    }
    assert!(
        defense.suspends().is_empty(),
        "allowed connections to .20 and 2001:db8::1 must never suspend the process"
    );
    assert!(
        store.list_alerts(None, 20).expect("list alerts").is_empty(),
        "allowed connections to .20 and 2001:db8::1 must emit zero alerts"
    );

    // Part 2 (`R-03`): Park a `WfpDropEvent` for a rotated target IP `198.51.100.30` during the
    // grace window, then inject a genuinely stale `A` response (`t=500 < latest IPv4 t=2000`).
    // The stale response must be rejected without minting a Permit and without prematurely waking
    // the parked drop into a false suspend/alert.
    let v4_next = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 30));
    assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
        os_filter_id: 43,
        rule_handle: 43,
        exe_path: exe.to_string(),
        protocol: 6,
        dst_ip: v4_next,
        dst_port: 443,
        timestamp_ms: base_ts + 3_300,
    }));

    // Synchronize via a Tier-3 Telemetry event: `run_pipeline` drains Tier-2b (`wfp_drop_rx`)
    // strictly before Tier-3 Telemetry, so once this Telemetry event completes, `v4_next` is
    // deterministically parked inside `pending_wfp_drops`.
    let before_tel = engine.metrics().telemetry_processed;
    engine
        .sender()
        .send(SensorEvent::DnsQuery {
            pid: 99_999,
            query_name: "tier3-barrier.local".to_string(),
            query_type: 1,
            resolved_ips: Vec::new(),
            timestamp_ms: base_ts + 3_301,
        })
        .await
        .expect("send tier3 telemetry barrier");
    assert!(
        wait_until(1_000, || engine.metrics().telemetry_processed > before_tel).await,
        "Tier-3 barrier must confirm WfpDropEvent has been dequeued and parked"
    );

    // Send stale `A 198.51.100.30 (t=500)` for `good.example`.
    let hp_before = engine.metrics().high_priority_processed;
    classified
        .send(SensorEvent::DnsQuery {
            pid: p1.pid,
            query_name: "good.example".to_string(),
            query_type: 1,
            resolved_ips: vec![v4_next],
            timestamp_ms: base_ts + 500,
        })
        .await
        .expect("send stale A .30 t=500");
    assert!(
        wait_until(1_000, || engine.metrics().high_priority_processed
            > hp_before)
        .await,
        "stale A (t=500) must finish pipeline processing"
    );
    assert!(
        !engine.has_active_wfp_filter(exe, Some(v4_next), true),
        "stale A (t=500 < latest IPv4 t=2000) must be rejected and must not materialize Permit"
    );
    assert!(
        defense.suspends().is_empty(),
        "rejected stale A (t=500) must NOT prematurely flush parked WfpDropEvent into false suspend"
    );
    assert!(
        store.list_alerts(None, 20).expect("list alerts").is_empty(),
        "rejected stale A (t=500) must NOT trigger a false alert"
    );

    // Now deliver the real fresh `A 198.51.100.30 (t=3500)` within the grace window: this must
    // authorize the parked `WfpDropEvent`, install `.30`'s Permit, and keep IPv6 Permit intact.
    let hp_before = engine.metrics().high_priority_processed;
    classified
        .send(SensorEvent::DnsQuery {
            pid: p1.pid,
            query_name: "good.example".to_string(),
            query_type: 1,
            resolved_ips: vec![v4_next],
            timestamp_ms: base_ts + 3_500,
        })
        .await
        .expect("send fresh A .30 t=3500");
    assert!(
        wait_until(1_000, || {
            engine.metrics().high_priority_processed > hp_before
                && engine.has_active_wfp_filter(exe, Some(v4_next), true)
        })
        .await,
        "fresh A (t=3500) within grace window must authorize parked drop and materialize .30 Permit"
    );
    assert!(
        engine.has_active_wfp_filter(exe, Some(v6_t3000), true),
        "IPv6 2001:db8::1 Permit must remain active after fresh IPv4 rotation"
    );

    // Shutdown flushes any remaining pending drops immediately, confirming the parked drop was
    // resolved cleanly without suspending or alerting.
    engine.shutdown_and_flush().await.expect("shutdown");
    assert!(
        defense.suspends().is_empty(),
        "no suspend must occur across full dual-stack + stale/fresh grace sequence"
    );
    assert!(
        store.list_alerts(None, 20).expect("list alerts").is_empty(),
        "no alert must occur across full dual-stack + stale/fresh grace sequence"
    );
}

/// `DAEMON-P3-44` (`R-13`, `L-10`): Deterministically pause the pipeline worker via
/// `GateBinaryInspector` so `wfp_drop_tx` (capacity 4) and `wfp_drop_overflow.queue` (capacity 4)
/// fill completely, then inject multiple distinct destination IPs for the same `app_exe` plus
/// distinct other executables into `coalesced_by_exe`. Before releasing the gate, verify both
/// `wfp_drop_overflow_pushed() > 0` and `wfp_drop_overflow_coalesced() > 0`; after releasing,
/// verify the latest coalesced destination IP for `app_exe` alerts and all other apps alert with
/// zero loss.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_p3_44_deterministic_wfp_drop_overflow_coalescing_preserves_latest_and_other_apps() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let entered = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    let inspector = Arc::new(GateBinaryInspector {
        target_substr: "wfp_overflow_gate.exe".to_string(),
        entered: Arc::clone(&entered),
        release: Arc::clone(&release),
        wait_cap: Duration::from_secs(5),
    });

    let gate_exe = r"C:\Tools\wfp_overflow_gate.exe";
    let app_exe = r"C:\Temp\coalesce_app.exe";
    let other_1 = r"C:\Temp\coalesce_other_1.exe";
    let other_2 = r"C:\Temp\coalesce_other_2.exe";
    let other_3 = r"C:\Temp\coalesce_other_3.exe";
    let now_ms = current_unix_ms();

    let engine = start_test_engine(
        store.clone(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            high_priority_capacity: 4,
            telemetry_capacity: 64,
            preemptive_startup_executables: vec![
                app_exe.to_string(),
                other_1.to_string(),
                other_2.to_string(),
                other_3.to_string(),
            ],
            wfp_drop_dns_grace_ms: 0,
            ..DaemonConfig::default()
        },
        defense,
        notifier,
        inspector,
    );

    // Start gate process, 2 instances of `app_exe` (multi-instance -> AppWfpAlertDedup per
    // `(exe, dst_ip)`), and 1 instance each of 3 distinct other apps (`coalesced_by_exe` cap = 4).
    let gate_proc = ProcessIdentity::new(9500, unix_ms_to_filetime(now_ms - 1_000));
    for (proc_id, exe) in [
        (gate_proc, gate_exe),
        (
            ProcessIdentity::new(9501, unix_ms_to_filetime(now_ms - 900)),
            app_exe,
        ),
        (
            ProcessIdentity::new(9502, unix_ms_to_filetime(now_ms - 800)),
            app_exe,
        ),
        (
            ProcessIdentity::new(9511, unix_ms_to_filetime(now_ms - 700)),
            other_1,
        ),
        (
            ProcessIdentity::new(9512, unix_ms_to_filetime(now_ms - 600)),
            other_2,
        ),
        (
            ProcessIdentity::new(9513, unix_ms_to_filetime(now_ms - 500)),
            other_3,
        ),
    ] {
        engine
            .sender()
            .send(SensorEvent::ProcessStart {
                identity: proc_id,
                parent_pid: 4,
                exe_path: exe.to_string(),
                command_line: exe.to_string(),
                user_sid: None,
            })
            .await
            .expect("start test process");
    }
    assert!(
        wait_until(1_000, || {
            engine.active_process_table_len() == 6 && engine.metrics().high_priority_processed >= 6
        })
        .await,
        "all 6 test processes must be registered before pausing worker"
    );

    // Pause the worker deterministically inside `GateBinaryInspector::inspect`.
    let gate_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 250));
    engine
        .classified_sender()
        .send(SensorEvent::NetworkConnect {
            pid: gate_proc.pid,
            protocol: 6,
            dst_ip: gate_ip,
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms,
        })
        .await
        .expect("send gate NetworkConnect");
    assert!(
        wait_until(2_000, || entered.load(Ordering::Acquire)).await,
        "worker must deterministically pause inside GateBinaryInspector"
    );

    // While the worker is paused:
    // - 1..=4 fill `wfp_drop_tx` (capacity 4)
    // - 5..=8 fill `wfp_drop_overflow.queue` (capacity 4 -> pushed = 4)
    // - 9 inserts `app_exe` into `coalesced_by_exe` (pushed = 5, coalesced = 0)
    // - 10 & 11 overwrite `app_exe` in `coalesced_by_exe` with newer dst IPs (coalesced = 2)
    for i in 1u8..=11 {
        assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
            os_filter_id: u64::from(i),
            rule_handle: u64::from(i),
            exe_path: app_exe.to_string(),
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, i)),
            dst_port: 8443,
            timestamp_ms: now_ms + i64::from(i),
        }));
    }
    // Distinct other apps fill the remaining 3 slots of `coalesced_by_exe` (total 4 == cap 4,
    // zero evictions; pushed = 8, coalesced = 2).
    let other_drops = [
        (other_1, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 101)), 101u64),
        (other_2, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 102)), 102u64),
        (other_3, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 103)), 103u64),
    ];
    for (exe, dst_ip, id) in other_drops {
        assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
            os_filter_id: id,
            rule_handle: id,
            exe_path: exe.to_string(),
            protocol: 6,
            dst_ip,
            dst_port: 8443,
            timestamp_ms: now_ms + id as i64,
        }));
    }

    // Deterministic pre-release verification of overflow & coalescing counters.
    assert!(
        engine.wfp_drop_overflow_pushed() > 0,
        "overflow fallback queue must be exercised while worker is paused"
    );
    assert_eq!(
        engine.wfp_drop_overflow_pushed(),
        8,
        "expected 4 queued + 4 distinct coalesced_by_exe entries pushed to overflow"
    );
    assert!(
        engine.wfp_drop_overflow_coalesced() > 0,
        "same-exe distinct destinations past overflow capacity must coalesce deterministically"
    );
    assert_eq!(
        engine.wfp_drop_overflow_coalesced(),
        2,
        "expected exactly 2 same-exe overwrites (.9 -> .10 -> .11) in coalesced_by_exe"
    );

    // Release the gate and wait for all 13 surviving alerts:
    // 1 (gate_proc) + 4 (wfp_drop_tx) + 4 (overflow.queue) + 1 (app_exe latest .11) + 3 (other_1..3).
    release.store(true, Ordering::Release);
    assert!(
        wait_until(3_000, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 50)
                .map(|v| v.len() == 13)
                .unwrap_or(false)
        })
        .await,
        "expected 13 Pending alerts after gate release (got {:?})",
        store
            .list_alerts(Some(AlertStatus::Pending), 50)
            .map(|v| v.len())
    );

    let alerts = store
        .list_alerts(Some(AlertStatus::Pending), 50)
        .expect("list pending alerts");
    let observed_pairs: Vec<(String, String)> = alerts
        .iter()
        .map(|a| {
            let v: serde_json::Value =
                serde_json::from_str(&a.context_json).expect("parse alert context_json");
            let exe = v
                .get("exe_path")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_ascii_lowercase();
            let ip = v
                .get("dst_ip")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string();
            (exe, ip)
        })
        .collect();

    let app_lower = app_exe.to_ascii_lowercase();
    for i in 1u8..=8 {
        let expected_ip = format!("203.0.113.{i}");
        assert!(
            observed_pairs
                .iter()
                .any(|(e, ip)| e == &app_lower && ip == &expected_ip),
            "queued app_exe drop {expected_ip} must reach triage: {observed_pairs:?}"
        );
    }
    assert!(
        observed_pairs
            .iter()
            .any(|(e, ip)| e == &app_lower && ip == "203.0.113.11"),
        "latest coalesced destination IP (203.0.113.11) for app_exe must reach triage: {observed_pairs:?}"
    );
    for overwritten_ip in ["203.0.113.9", "203.0.113.10"] {
        assert!(
            !observed_pairs
                .iter()
                .any(|(e, ip)| e == &app_lower && ip == overwritten_ip),
            "superseded coalesced destination {overwritten_ip} should have been overwritten by .11"
        );
    }
    for (other_exe, other_ip, _) in other_drops {
        let other_lower = other_exe.to_ascii_lowercase();
        let ip_str = other_ip.to_string();
        assert!(
            observed_pairs
                .iter()
                .any(|(e, ip)| e == &other_lower && ip == &ip_str),
            "distinct app {other_exe} -> {ip_str} must alert with zero loss: {observed_pairs:?}"
        );
    }

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P3-45` (`R-11` / `AUTO-10`): When the background NRD refresh OS thread remains blocked
/// past `shutdown_flush_timeout_ms` (simulated deterministically without external network via an
/// open local Windows Named Pipe `file://./pipe/...` held by an independent server thread),
/// `shutdown_and_flush` still completes SQLite `wal_checkpoint(TRUNCATE)` within budget and
/// detaches the NRD OS thread without spawning a Tokio blocking join task, so dropping the
/// independently constructed Tokio `Runtime` completes promptly without hanging.
#[test]
fn daemon_p3_45_over_budget_nrd_shutdown_checkpoints_and_runtime_drop_does_not_hang() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::windows::named_pipe::ServerOptions;

    struct TempDirGuard(std::path::PathBuf);
    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct PipeServerGuard {
        release_tx: Option<tokio::sync::oneshot::Sender<()>>,
        thread: Option<std::thread::JoinHandle<()>>,
    }
    impl PipeServerGuard {
        fn stop_and_join(&mut self) {
            if let Some(tx) = self.release_tx.take() {
                let _ = tx.send(());
            }
            if let Some(jh) = self.thread.take() {
                let _ = jh.join();
            }
        }
    }
    impl Drop for PipeServerGuard {
        fn drop(&mut self) {
            self.stop_and_join();
        }
    }

    let tmp_dir = std::env::temp_dir().join(format!(
        "ledr-p3-45-nrd-shutdown-{}-{}",
        std::process::id(),
        PIPE_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&tmp_dir).expect("create temp dir for DAEMON-P3-45");
    let _tmp_guard = TempDirGuard(tmp_dir.clone());
    let db_path = tmp_dir.join("nrd_overbudget.db");

    let pipe_leaf = format!(
        "localedr-p3-45-nrd-hang-{}-{}",
        std::process::id(),
        PIPE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let pipe_path = format!(r"\\.\pipe\{pipe_leaf}");
    let feed_url = format!("file://./pipe/{pipe_leaf}");
    assert_eq!(
        ledr_rules::parse_file_url(&feed_url).expect("parse pipe file:// URL"),
        std::path::PathBuf::from(&pipe_path),
        "file://./pipe/... URL must resolve to the local Windows Named Pipe path"
    );

    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let server_released = Arc::new(AtomicBool::new(false));
    let released_bg = Arc::clone(&server_released);
    let pipe_path_bg = pipe_path.clone();

    let server_thread = std::thread::Builder::new()
        .name("test-nrd-pipe-server".to_string())
        .spawn(move || {
            let pipe_rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build helper pipe runtime");
            pipe_rt.block_on(async move {
                let mut server = ServerOptions::new()
                    .first_pipe_instance(true)
                    .out_buffer_size(1024)
                    .create(&pipe_path_bg)
                    .expect("create local Named Pipe for NRD hang simulation");
                let _ = ready_tx.send(());

                let mut release_rx = release_rx;
                let connected = tokio::select! {
                    res = server.connect() => res.is_ok(),
                    _ = &mut release_rx => false,
                    _ = tokio::time::sleep(Duration::from_secs(10)) => false,
                };
                if connected {
                    // Write only a single byte `b"\n"` and flush, then hold the pipe open until
                    // `release_rx` fires: the 1st `ReadFile` consumes that byte
                    // (`blocking_read_entries() == 1`), guaranteeing the 2nd `ReadFile` blocks
                    // in the kernel with 0 bytes remaining (`blocking_read_entries() >= 2 &&
                    // is_blocking_read_active()`).
                    let wrote = tokio::select! {
                        res = async {
                            server.write_all(b"\n").await?;
                            server.flush().await
                        } => res.is_ok(),
                        _ = &mut release_rx => false,
                        _ = tokio::time::sleep(Duration::from_secs(5)) => false,
                    };
                    if wrote {
                        let _ =
                            tokio::time::timeout(Duration::from_secs(10), &mut release_rx).await;
                    }
                    let _ = server.disconnect();
                }
                released_bg.store(true, Ordering::Release);
                drop(server);
            });
        })
        .expect("spawn helper Named Pipe server thread");

    let mut pipe_guard = PipeServerGuard {
        release_tx: Some(release_tx),
        thread: Some(server_thread),
    };
    ready_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("Named Pipe server must become ready");

    // Build an independent Tokio Runtime so we can explicitly time `Runtime::drop` right after
    // `shutdown_and_flush` returns while the detached NRD thread is still blocked in `ReadFile`.
    let subject_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("build independent Tokio runtime");

    let now_ms = current_unix_ms();
    let marker_proc = ProcessIdentity::new(9601, unix_ms_to_filetime(now_ms - 1_000));
    let marker_id = marker_proc.instance_id();

    let marker_id_for_rt = marker_id.clone();
    let db_path_for_rt = db_path.clone();
    subject_rt.block_on(async move {
        let store = LedrStore::open(&db_path_for_rt).expect("open file-backed LedrStore");
        let defense = Arc::new(MockWfpDefense::new());
        let notifier = Arc::new(MockNotifier::default());
        let inspector = Arc::new(MapBinaryInspector::default());

        let engine = start_test_engine(store.clone(),
            DaemonConfig {
                pipe_name: unique_test_pipe_name(),
                nrd_refresh_enabled: true,
                nrd_refresh_interval_ms: 200,
                nrd_feed_urls: vec![feed_url],
                shutdown_flush_timeout_ms: 600,
                batch_flush_interval_ms: 500,
                ..DaemonConfig::default()
            },
            defense,
            notifier,
            inspector,
        );

        let nrd_token = engine.nrd_cancel_token();
        assert!(
            wait_until(3_000, || {
                nrd_token.blocking_read_entries() >= 2
                    && nrd_token.is_blocking_read_active()
                    && engine.is_nrd_refresh_in_flight()
            })
            .await,
            "background NRD thread must enter its 2nd blocking ReadFile on local Named Pipe"
        );

        // Sending and synchronizing a ProcessStart AFTER observing `blocking_read_entries() >= 2`
        // simultaneously:
        // 1. guarantees `run_pipeline` has finished storing `NrdThreadHandle` on the same task, and
        // 2. writes dirty state into SQLite WAL so we can verify `wal_checkpoint(TRUNCATE)`.
        engine
            .sender()
            .send(SensorEvent::ProcessStart {
                identity: marker_proc,
                parent_pid: 4,
                exe_path: r"C:\Tools\nrd_shutdown_marker.exe".to_string(),
                command_line: r"C:\Tools\nrd_shutdown_marker.exe".to_string(),
                user_sid: None,
            })
            .await
            .expect("send marker ProcessStart");
        assert!(
            wait_until(1_000, || {
                engine.active_process_table_len() == 1
                    && engine.metrics().high_priority_processed >= 1
            })
            .await,
            "marker ProcessStart must be processed before shutdown"
        );

        let shutdown_started = Instant::now();
        engine
            .shutdown_and_flush()
            .await
            .expect("shutdown_and_flush must checkpoint and return Ok despite over-budget NRD");
        let shutdown_elapsed = shutdown_started.elapsed();

        assert!(
            shutdown_elapsed < Duration::from_millis(2_000),
            "shutdown_and_flush must return within budget without hanging (took {shutdown_elapsed:?})"
        );
        assert!(
            engine.is_nrd_refresh_in_flight(),
            "NRD refresh thread must still be blocked past budget so the detach path was genuinely exercised"
        );
        assert_eq!(
            Arc::strong_count(&engine),
            1,
            "detached NRD thread must hold zero Arc<DaemonEngine> references"
        );

        let persisted = store
            .list_running_process_instance_ids()
            .expect("list persisted running processes");
        assert!(
            persisted.contains(&marker_id_for_rt),
            "marker process {marker_id_for_rt} must be flushed before shutdown returns"
        );
        let wal_path = std::path::PathBuf::from(format!("{}-wal", db_path_for_rt.display()));
        if wal_path.exists() {
            let wal_len = std::fs::metadata(&wal_path).expect("stat wal").len();
            assert_eq!(
                wal_len, 0,
                "SQLite WAL must be truncated to 0 bytes before shutdown_and_flush returns"
            );
        }

        drop(engine);
        drop(store);
    });

    assert!(
        !server_released.load(Ordering::Acquire),
        "Named Pipe server must still be holding the NRD thread blocked when Runtime::drop starts"
    );
    let drop_started = Instant::now();
    drop(subject_rt);
    let drop_elapsed = drop_started.elapsed();
    assert!(
        drop_elapsed < Duration::from_millis(500),
        "independent Tokio Runtime::drop must complete promptly without hanging on detached NRD thread (took {drop_elapsed:?})"
    );

    // Release and join the helper Named Pipe server so the detached NRD OS thread unblocks cleanly.
    pipe_guard.stop_and_join();

    // Verify durability on reopen after Runtime::drop.
    {
        let reopened = LedrStore::open(&db_path).expect("reopen checkpointed LedrStore");
        let persisted = reopened
            .list_running_process_instance_ids()
            .expect("query reopened processes");
        assert!(
            persisted.contains(&marker_id),
            "checkpointed marker process {marker_id} must survive runtime teardown"
        );
        let wal_path = std::path::PathBuf::from(format!("{}-wal", db_path.display()));
        if wal_path.exists() {
            let wal_len = std::fs::metadata(&wal_path)
                .expect("stat reopened wal")
                .len();
            assert_eq!(wal_len, 0, "reopened DB must have 0-byte WAL");
        }
    }
}

/// `DAEMON-P3-46` (PR #5 Issue #2 regression, `L-03` / `L-10` / `AUTO-05`):
/// 1. Under a pre-emptively restricted single process with a `NetworkAllow` rule ONLY for
///    `allowed.example`, when `other.example (t=2000)` resolves first to a shared IP
///    (`198.51.100.77`), an earlier `WfpDropEvent` is parked/queued, and late-arriving
///    `allowed.example (t=1500 < 2000)` arrives via the high-priority lane: `allowed.example`'s
///    IP Permit is materialized and preserved through `handle_wfp_drop_event_now` with zero
///    suspends and zero false alerts.
/// 2. When `blocked.example` (`NetworkBlock` rule) also coexists on that same shared IP alongside
///    `allowed.example`, deny-overrides-allow revokes/withholds the IP Permit, installs and keeps
///    the `DomainPolicy` IP Block, and emits `LEDR-NET-POLICY-BLOCK` during WFP drop triage even
///    when `allowed.example` has a newer DNS timestamp.
#[tokio::test]
async fn daemon_p3_46_shared_ip_late_allowed_dns_vs_earlier_wfp_drop_and_deny_overrides_allow() {
    let shared_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77));
    let now_ms = current_unix_ms();
    let base_ts = now_ms - 4_000;

    // -------------------------------------------------------------------------
    // Part 1: Shared IP late allowed DNS (t=1500) vs newer unallowed DNS (t=2000)
    // and earlier WFP drop.
    // -------------------------------------------------------------------------
    {
        let store = LedrStore::open_in_memory().expect("open store");
        let defense = Arc::new(MockWfpDefense::new());
        let notifier = Arc::new(MockNotifier::default());
        let inspector = Arc::new(MapBinaryInspector::default());

        let exe = r"C:\Temp\shared_ip_allow_p3_46.exe";
        let sha = "b".repeat(64);
        inspector.register(exe, Some(&sha), None);

        store
            .upsert_rule(&AllowlistRuleRecord {
                rule_id: "R-ALLOW-SHARED-P3-46".to_string(),
                scope: RuleScope::NetworkAllow,
                exe_path_pattern: exe.to_string(),
                sha256: Some(sha),
                signer_subject: None,
                root_thumbprint: None,
                allowed_target: Some("allowed.example".to_string()),
                created_at_ms: now_ms - 10_000,
                created_by: "seed".to_string(),
            })
            .expect("seed allowed.example allow rule");

        let engine = start_test_engine(
            store.clone(),
            DaemonConfig {
                pipe_name: unique_test_pipe_name(),
                preemptive_startup_executables: vec![exe.to_string()],
                wfp_drop_dns_grace_ms: 2_000,
                ..DaemonConfig::default()
            },
            defense.clone(),
            notifier,
            inspector,
        );

        let p1 = ProcessIdentity::new(9701, unix_ms_to_filetime(now_ms - 10_000));
        engine
            .sender()
            .send(SensorEvent::ProcessStart {
                identity: p1,
                parent_pid: 4,
                exe_path: exe.to_string(),
                command_line: exe.to_string(),
                user_sid: None,
            })
            .await
            .expect("start single pre-restricted process");
        assert!(
            wait_until(1_000, || {
                engine.active_process_table_len() == 1
                    && engine.metrics().high_priority_processed >= 1
            })
            .await,
            "ProcessStart must complete before DNS sequence"
        );
        assert!(
            engine.has_active_wfp_filter(exe, None, false),
            "pre-restricted process must have an active app-wide WFP block"
        );

        let classified = engine.classified_sender();

        // Step 1: Newer unallowed `other.example (t=2000)` resolves to `shared_ip`.
        let dns_other = SensorEvent::DnsQuery {
            pid: p1.pid,
            query_name: "other.example".to_string(),
            query_type: 1,
            resolved_ips: vec![shared_ip],
            timestamp_ms: base_ts + 2_000,
        };
        assert!(
            classified.should_promote(&dns_other),
            "external DnsQuery with active domain allow rule must promote to HighPriority"
        );
        let hp_before = engine.metrics().high_priority_processed;
        classified
            .send(dns_other)
            .await
            .expect("send other.example DNS");
        assert!(
            wait_until(1_000, || engine.metrics().high_priority_processed
                > hp_before)
            .await,
            "other.example (t=2000) DnsQuery must finish HighPriority processing"
        );
        assert!(
            !engine.has_active_wfp_filter(exe, Some(shared_ip), true),
            "unallowed other.example must not materialize an IP Permit"
        );

        // Step 2: Earlier WFP drop for `shared_ip` arrives while only `other.example` is known.
        // Synchronize via a Tier-3 Telemetry barrier (`run_pipeline` drains Tier-2b `wfp_drop_rx`
        // strictly before Tier-3 Telemetry) to confirm the drop is deterministically dequeued and
        // parked inside `pending_wfp_drops` during the grace window.
        assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
            os_filter_id: 4601,
            rule_handle: 4601,
            exe_path: exe.to_string(),
            protocol: 6,
            dst_ip: shared_ip,
            dst_port: 443,
            timestamp_ms: base_ts + 2_050,
        }));
        let tel_before = engine.metrics().telemetry_processed;
        engine
            .sender()
            .send(SensorEvent::DnsQuery {
                pid: 99_999,
                query_name: "p3-46-park-barrier.local".to_string(),
                query_type: 1,
                resolved_ips: Vec::new(),
                timestamp_ms: base_ts + 2_051,
            })
            .await
            .expect("send Tier-3 park barrier");
        assert!(
            wait_until(1_000, || engine.metrics().telemetry_processed > tel_before).await,
            "Tier-3 barrier must confirm earlier WfpDropEvent has been dequeued and parked"
        );
        assert!(
            defense.suspends().is_empty(),
            "parked WfpDropEvent must not suspend before late allowed DNS arrives"
        );
        assert!(
            store.list_alerts(None, 20).expect("list alerts").is_empty(),
            "parked WfpDropEvent must not emit an alert before late allowed DNS arrives"
        );
        assert!(
            !engine.has_active_wfp_filter(exe, Some(shared_ip), true),
            "no IP Permit must exist prior to late allowed.example DNS"
        );

        // Step 3: Late-arriving `allowed.example (t=1500 < 2000)` arrives on HighPriority lane:
        // pre-materializes the IP Permit and immediately wakes the parked earlier WFP drop into
        // `handle_wfp_drop_event_now` with both `other.example (t=2000)` and `allowed.example (t=1500)`
        // in `ProcessDnsHistory`.
        let dns_allowed = SensorEvent::DnsQuery {
            pid: p1.pid,
            query_name: "allowed.example".to_string(),
            query_type: 1,
            resolved_ips: vec![shared_ip],
            timestamp_ms: base_ts + 1_500,
        };
        assert!(
            classified.should_promote(&dns_allowed),
            "late allowed.example DnsQuery must promote to HighPriority lane"
        );
        let hp_before = engine.metrics().high_priority_processed;
        classified
            .send(dns_allowed)
            .await
            .expect("send late allowed.example DNS");
        assert!(
            wait_until(1_000, || engine.metrics().high_priority_processed
                > hp_before)
            .await,
            "late allowed.example (t=1500) DnsQuery must complete HighPriority processing"
        );
        // Follow with a Tier-3 Telemetry barrier so `flush_ready_pending_wfp_drops` ->
        // `handle_wfp_drop_event_now` (which runs right after `high_priority_processed` increments
        // in the same worker loop iteration) is deterministically complete before assertions.
        let tel_before = engine.metrics().telemetry_processed;
        engine
            .sender()
            .send(SensorEvent::DnsQuery {
                pid: 99_999,
                query_name: "p3-46-flush-barrier.local".to_string(),
                query_type: 1,
                resolved_ips: Vec::new(),
                timestamp_ms: base_ts + 2_060,
            })
            .await
            .expect("send Tier-3 post-wakeup barrier");
        assert!(
            wait_until(1_000, || engine.metrics().telemetry_processed > tel_before).await,
            "Tier-3 barrier must confirm parked WfpDropEvent completed handle_wfp_drop_event_now"
        );

        // Step 4: Also exercise direct post-DNS `handle_wfp_drop_event_now` on a distinct port
        // while both `other.example (t=2000)` and `allowed.example (t=1500)` coexist in DNS history.
        assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
            os_filter_id: 4602,
            rule_handle: 4602,
            exe_path: exe.to_string(),
            protocol: 6,
            dst_ip: shared_ip,
            dst_port: 8443,
            timestamp_ms: base_ts + 2_100,
        }));
        let tel_before = engine.metrics().telemetry_processed;
        engine
            .sender()
            .send(SensorEvent::DnsQuery {
                pid: 99_999,
                query_name: "p3-46-direct-drop-barrier.local".to_string(),
                query_type: 1,
                resolved_ips: Vec::new(),
                timestamp_ms: base_ts + 2_101,
            })
            .await
            .expect("send Tier-3 post-direct-drop barrier");
        assert!(
            wait_until(1_000, || engine.metrics().telemetry_processed > tel_before).await,
            "Tier-3 barrier must confirm direct WfpDropEvent completed handle_wfp_drop_event_now"
        );

        assert!(
            engine.has_active_wfp_filter(exe, Some(shared_ip), true),
            "IP Permit for allowed.example on shared IP must be preserved after WFP drop triage"
        );
        assert!(
            defense.removed_wfp().is_empty(),
            "allowed.example IP Permit must never be revoked during shared-IP WFP drop triage"
        );
        assert_eq!(
            defense.suspends().len(),
            0,
            "process must NOT be suspended when allowed.example coexists with newer other.example"
        );
        assert!(
            store.list_alerts(None, 20).expect("list alerts").is_empty(),
            "zero false alerts must be emitted when allowed.example coexists on shared IP"
        );

        // Shutdown also flushes any remaining pending drops immediately, confirming zero late alerts/suspends.
        engine.shutdown_and_flush().await.expect("shutdown part 1");
        assert_eq!(
            defense.suspends().len(),
            0,
            "zero suspends must remain after shutdown flush"
        );
        assert!(
            store.list_alerts(None, 20).expect("list alerts").is_empty(),
            "zero false alerts must remain after shutdown flush"
        );
    }

    // -------------------------------------------------------------------------
    // Part 2: `blocked.example` (`NetworkBlock`) coexisting on the same shared IP
    // alongside `allowed.example` (`NetworkAllow`) enforces deny-overrides-allow.
    // -------------------------------------------------------------------------
    {
        let store = LedrStore::open_in_memory().expect("open store part 2");
        let defense = Arc::new(MockWfpDefense::new());
        let notifier = Arc::new(MockNotifier::default());
        let inspector = Arc::new(MapBinaryInspector::default());

        let exe2 = r"C:\Temp\shared_ip_coexist_p3_46.exe";
        let sha2 = "c".repeat(64);
        inspector.register(exe2, Some(&sha2), None);

        store
            .upsert_rule(&AllowlistRuleRecord {
                rule_id: "R-ALLOW-COEXIST-P3-46".to_string(),
                scope: RuleScope::NetworkAllow,
                exe_path_pattern: exe2.to_string(),
                sha256: Some(sha2.clone()),
                signer_subject: None,
                root_thumbprint: None,
                allowed_target: Some("allowed.example".to_string()),
                created_at_ms: now_ms - 10_000,
                created_by: "seed".to_string(),
            })
            .expect("seed allowed.example rule");
        store
            .upsert_rule(&AllowlistRuleRecord {
                rule_id: "R-BLK-COEXIST-P3-46".to_string(),
                scope: RuleScope::NetworkBlock,
                exe_path_pattern: exe2.to_string(),
                sha256: Some(sha2),
                signer_subject: None,
                root_thumbprint: None,
                allowed_target: Some("blocked.example".to_string()),
                created_at_ms: now_ms - 9_999,
                created_by: "seed".to_string(),
            })
            .expect("seed blocked.example rule");

        let engine2 = start_test_engine(
            store.clone(),
            DaemonConfig {
                pipe_name: unique_test_pipe_name(),
                preemptive_startup_executables: vec![exe2.to_string()],
                wfp_drop_dns_grace_ms: 2_000,
                ..DaemonConfig::default()
            },
            defense.clone(),
            notifier,
            inspector,
        );

        let p2 = ProcessIdentity::new(9702, unix_ms_to_filetime(now_ms - 10_000));
        engine2
            .sender()
            .send(SensorEvent::ProcessStart {
                identity: p2,
                parent_pid: 4,
                exe_path: exe2.to_string(),
                command_line: exe2.to_string(),
                user_sid: None,
            })
            .await
            .expect("start part 2 process");
        assert!(
            wait_until(1_000, || {
                engine2.active_process_table_len() == 1
                    && engine2.metrics().high_priority_processed >= 1
            })
            .await,
            "part 2 ProcessStart must complete"
        );

        let classified = engine2.classified_sender();

        // First resolve `allowed.example (t=2000)` -> IP Permit installed initially.
        let dns_allow_init = SensorEvent::DnsQuery {
            pid: p2.pid,
            query_name: "allowed.example".to_string(),
            query_type: 1,
            resolved_ips: vec![shared_ip],
            timestamp_ms: base_ts + 2_000,
        };
        assert!(classified.should_promote(&dns_allow_init));
        let hp_before = engine2.metrics().high_priority_processed;
        classified
            .send(dns_allow_init)
            .await
            .expect("send initial allowed.example DNS");
        assert!(
            wait_until(1_000, || engine2.metrics().high_priority_processed
                > hp_before)
            .await,
            "initial allowed.example DNS must complete"
        );
        assert!(
            engine2.has_active_wfp_filter(exe2, Some(shared_ip), true),
            "allowed.example should materialize IP Permit before blocked.example shares the IP"
        );

        // Next resolve `blocked.example (t=1500, older than allowed.example)` on the same shared IP:
        // deny-overrides-allow must revoke the IP Permit and install a DomainPolicy IP Block.
        let dns_blocked = SensorEvent::DnsQuery {
            pid: p2.pid,
            query_name: "blocked.example".to_string(),
            query_type: 1,
            resolved_ips: vec![shared_ip],
            timestamp_ms: base_ts + 1_500,
        };
        assert!(classified.should_promote(&dns_blocked));
        let hp_before = engine2.metrics().high_priority_processed;
        classified
            .send(dns_blocked)
            .await
            .expect("send blocked.example DNS");
        assert!(
            wait_until(1_000, || engine2.metrics().high_priority_processed
                > hp_before)
            .await,
            "blocked.example DNS must complete"
        );
        assert!(
            !engine2.has_active_wfp_filter(exe2, Some(shared_ip), true),
            "coexisting blocked.example must revoke allowed.example IP Permit (deny-overrides-allow)"
        );
        assert!(
            engine2.has_active_wfp_filter(exe2, Some(shared_ip), false),
            "coexisting blocked.example must install IP-level DomainPolicy Block"
        );

        // Re-resolving newer `allowed.example (t=2500)` on `shared_ip` must keep Permit withheld
        // while `blocked.example` remains active on the shared IP.
        let dns_allow_newer = SensorEvent::DnsQuery {
            pid: p2.pid,
            query_name: "allowed.example".to_string(),
            query_type: 1,
            resolved_ips: vec![shared_ip],
            timestamp_ms: base_ts + 2_500,
        };
        let hp_before = engine2.metrics().high_priority_processed;
        classified
            .send(dns_allow_newer)
            .await
            .expect("send newer allowed.example DNS");
        assert!(
            wait_until(1_000, || engine2.metrics().high_priority_processed
                > hp_before)
            .await,
            "newer allowed.example DNS must complete"
        );
        assert!(
            !engine2.has_active_wfp_filter(exe2, Some(shared_ip), true),
            "Permit must remain withheld when blocked.example coexists on shared IP"
        );
        assert!(
            engine2.has_active_wfp_filter(exe2, Some(shared_ip), false),
            "IP Block must remain active when newer allowed.example queries shared IP"
        );

        // WFP drop on `shared_ip` must enforce `BlockedByRule` even though `allowed.example (t=2500)`
        // is newer than `blocked.example (t=1500)`.
        assert!(engine2.ingest_wfp_drop_event(WfpDropEvent {
            os_filter_id: 4603,
            rule_handle: 4603,
            exe_path: exe2.to_string(),
            protocol: 6,
            dst_ip: shared_ip,
            dst_port: 443,
            timestamp_ms: base_ts + 2_600,
        }));
        let tel_before = engine2.metrics().telemetry_processed;
        engine2
            .sender()
            .send(SensorEvent::DnsQuery {
                pid: 99_999,
                query_name: "p3-46-coexist-drop-barrier.local".to_string(),
                query_type: 1,
                resolved_ips: Vec::new(),
                timestamp_ms: base_ts + 2_601,
            })
            .await
            .expect("send Tier-3 coexist barrier");
        assert!(
            wait_until(1_000, || engine2.metrics().telemetry_processed > tel_before).await,
            "Tier-3 barrier must confirm blocked coexist WfpDropEvent completed"
        );

        let alerts = store.list_alerts(None, 20).expect("list part 2 alerts");
        assert_eq!(
            alerts.len(),
            1,
            "coexisting blocked.example on shared IP must emit one policy-block alert (got {alerts:?})"
        );
        assert_eq!(alerts[0].rule_id, "LEDR-NET-POLICY-BLOCK");
        let ctx: serde_json::Value =
            serde_json::from_str(&alerts[0].context_json).expect("parse block alert context_json");
        assert_eq!(
            ctx.get("matched_rule_id")
                .and_then(serde_json::Value::as_str),
            Some("R-BLK-COEXIST-P3-46")
        );
        assert_eq!(
            ctx.get("domain_hint").and_then(serde_json::Value::as_str),
            Some("blocked.example")
        );
        assert_eq!(
            ctx.get("wfp_blocked").and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert!(
            !engine2.has_active_wfp_filter(exe2, Some(shared_ip), true),
            "IP Permit must remain absent after deny-overrides-allow drop enforcement"
        );
        assert!(
            engine2.has_active_wfp_filter(exe2, Some(shared_ip), false),
            "IP Block must remain enforced after deny-overrides-allow drop enforcement"
        );

        engine2.shutdown_and_flush().await.expect("shutdown part 2");
    }
}

/// `DAEMON-P3-47` (PR #5 Issue #4 regression, `L-03` / `L-10`):
/// With `DaemonConfig::dns_history_capacity = 4` and `NetworkBlock` rules for `a.example` and
/// `b.example`, resolving both to shared IP `198.51.100.88`, migrating `a.example` away (block
/// kept for `b.example`), flooding 6+ unrelated DNS queries across multiple processes so
/// `ProcessDnsHistory::latest_domain_by_exe` FIFO completely evicts `a.example`'s history, and
/// finally migrating `b.example` away must deterministically remove the stale `DomainPolicy`
/// block filter on `198.51.100.88`.
#[tokio::test]
async fn daemon_p3_47_shared_ip_block_cleanup_after_fifo_eviction_of_first_domain() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let exe = r"C:\Tools\shared_blk_evict_p3_47.exe";
    let other_exe = r"C:\Tools\unrelated_dns_p3_47.exe";
    let sha = "d".repeat(64);
    inspector.register(exe, Some(&sha), None);

    let now_ms = current_unix_ms();
    let base_ts = now_ms - 4_000;

    let engine = start_test_engine(
        store.clone(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            dns_history_capacity: 4,
            ..DaemonConfig::default()
        },
        defense.clone(),
        notifier,
        inspector,
    );

    for (rid, dom) in [
        ("R-BLK-P3-47-A", "a.example"),
        ("R-BLK-P3-47-B", "b.example"),
    ] {
        engine
            .upsert_policy_rule(&make_net_rule(
                rid,
                RuleScope::NetworkBlock,
                exe,
                Some(sha.as_str()),
                Some(dom),
                now_ms - 10_000,
                "seed",
            ))
            .expect("register NetworkBlock rule");
    }

    let p1 = ProcessIdentity::new(9801, unix_ms_to_filetime(now_ms - 10_000));
    let p2 = ProcessIdentity::new(9802, unix_ms_to_filetime(now_ms - 9_500));
    for (proc_id, path) in [(p1, exe), (p2, other_exe)] {
        engine
            .sender()
            .send(SensorEvent::ProcessStart {
                identity: proc_id,
                parent_pid: 4,
                exe_path: path.to_string(),
                command_line: path.to_string(),
                user_sid: None,
            })
            .await
            .expect("send ProcessStart");
    }
    assert!(
        wait_until(1_000, || {
            engine.active_process_table_len() == 2 && engine.metrics().high_priority_processed >= 2
        })
        .await,
        "both processes must be registered before DNS sequence"
    );

    let classified = engine.classified_sender();
    let shared_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 88));
    let a_new_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11));
    let b_new_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 22));

    // Step 1: Resolve `a.example` then `b.example` to shared IP `198.51.100.88`.
    for (dom, ts_off) in [("a.example", 100), ("b.example", 200)] {
        let ev = SensorEvent::DnsQuery {
            pid: p1.pid,
            query_name: dom.to_string(),
            query_type: 1,
            resolved_ips: vec![shared_ip],
            timestamp_ms: base_ts + ts_off,
        };
        assert!(
            classified.should_promote(&ev),
            "domain block rule must promote external DnsQuery for {dom} to HighPriority"
        );
        let hp_before = engine.metrics().high_priority_processed;
        classified.send(ev).await.expect("send shared-IP DNS");
        assert!(
            wait_until(1_000, || engine.metrics().high_priority_processed
                > hp_before)
            .await,
            "{dom} -> shared_ip DnsQuery must finish processing"
        );
    }
    assert!(
        engine.has_active_wfp_filter(exe, Some(shared_ip), false),
        "DomainPolicy Block filter must exist on shared IP 198.51.100.88"
    );

    // Step 2: Migrate `a.example` to `a_new_ip` -> shared IP block MUST remain active for `b.example`.
    let dns_a_migrate = SensorEvent::DnsQuery {
        pid: p1.pid,
        query_name: "a.example".to_string(),
        query_type: 1,
        resolved_ips: vec![a_new_ip],
        timestamp_ms: base_ts + 300,
    };
    assert!(classified.should_promote(&dns_a_migrate));
    let hp_before = engine.metrics().high_priority_processed;
    classified
        .send(dns_a_migrate)
        .await
        .expect("send a.example migration DNS");
    assert!(
        wait_until(1_000, || engine.metrics().high_priority_processed
            > hp_before)
        .await,
        "a.example migration DnsQuery must finish processing"
    );
    assert!(
        engine.has_active_wfp_filter(exe, Some(a_new_ip), false),
        "migrated a.example destination must receive a DomainPolicy Block"
    );
    assert!(
        engine.has_active_wfp_filter(exe, Some(shared_ip), false),
        "shared IP 198.51.100.88 block must be maintained while b.example still points there"
    );

    // Step 3: Submit 7 unrelated DNS queries across `p2` (another process) and `p1` (unrelated
    // domains) so `ProcessDnsHistory::latest_domain_by_exe` FIFO (capacity 4) completely evicts
    // `a.example`'s history.
    let noise_queries: [(u32, &str, u8); 7] = [
        (p2.pid, "other-proc-0.example", 101),
        (p2.pid, "other-proc-1.example", 102),
        (p2.pid, "other-proc-2.example", 103),
        (p2.pid, "other-proc-3.example", 104),
        (p1.pid, "unrelated-0.example", 105),
        (p1.pid, "unrelated-1.example", 106),
        (p1.pid, "unrelated-2.example", 107),
    ];
    for (idx, (pid, domain, octet)) in noise_queries.into_iter().enumerate() {
        let ev = SensorEvent::DnsQuery {
            pid,
            query_name: domain.to_string(),
            query_type: 1,
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, octet))],
            timestamp_ms: base_ts + 350 + idx as i64,
        };
        let promoted = classified.should_promote(&ev);
        let hp_before = engine.metrics().high_priority_processed;
        let tel_before = engine.metrics().telemetry_processed;
        classified.send(ev).await.expect("send FIFO noise DNS");
        assert!(
            wait_until(1_000, || {
                if promoted {
                    engine.metrics().high_priority_processed > hp_before
                } else {
                    engine.metrics().telemetry_processed > tel_before
                }
            })
            .await,
            "FIFO eviction DNS query {domain} must finish processing on its lane"
        );
    }
    assert!(
        engine.has_active_wfp_filter(exe, Some(shared_ip), false),
        "shared IP 198.51.100.88 block must remain active after DNS FIFO eviction while b.example has not migrated"
    );

    // Step 4: Migrate `b.example` to `b_new_ip` -> old shared IP `198.51.100.88` DomainPolicy
    // Block filter MUST be deterministically removed despite `a.example` having been FIFO-evicted.
    let dns_b_migrate = SensorEvent::DnsQuery {
        pid: p1.pid,
        query_name: "b.example".to_string(),
        query_type: 1,
        resolved_ips: vec![b_new_ip],
        timestamp_ms: base_ts + 500,
    };
    assert!(classified.should_promote(&dns_b_migrate));
    let hp_before = engine.metrics().high_priority_processed;
    classified
        .send(dns_b_migrate)
        .await
        .expect("send b.example migration DNS");
    assert!(
        wait_until(1_000, || engine.metrics().high_priority_processed
            > hp_before)
        .await,
        "b.example migration DnsQuery must finish processing"
    );
    assert!(
        !engine.has_active_wfp_filter(exe, Some(shared_ip), false),
        "stale DomainPolicy Block on 198.51.100.88 must be deterministically removed after b.example migrates"
    );
    assert!(
        engine.has_active_wfp_filter(exe, Some(b_new_ip), false),
        "migrated b.example destination must receive a DomainPolicy Block"
    );
    assert!(
        engine.has_active_wfp_filter(exe, Some(a_new_ip), false),
        "previously migrated a.example destination block must remain active"
    );
    assert!(
        !defense.removed_wfp().is_empty(),
        "WFP remove_wfp_rule must have been invoked to clean up retired shared IP block"
    );

    engine.shutdown_and_flush().await.expect("shutdown");
}

struct P348Harness {
    store: LedrStore,
    defense: Arc<MockWfpDefense>,
    notifier: Arc<MockNotifier>,
    inspector: Arc<MapBinaryInspector>,
    engine: Arc<DaemonEngine>,
    ps_exe: &'static str,
    ps_sha: String,
    unrelated_exe: &'static str,
    unrelated_sha: String,
    ps_proc: ProcessIdentity,
}

impl P348Harness {
    async fn start(pid: u32, allow_rules: &[(&str, &str)], base_ts: i64) -> Self {
        let store = LedrStore::open_in_memory().expect("open store");
        let defense = Arc::new(MockWfpDefense::new());
        let notifier = Arc::new(MockNotifier::default());
        let inspector = Arc::new(MapBinaryInspector::default());

        let ps_exe = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
        let ps_sha = "a".repeat(64);
        let unrelated_exe = r"C:\Tools\unrelated_app_p3_48.exe";
        let unrelated_sha = "b".repeat(64);
        inspector.register(ps_exe, Some(&ps_sha), None);
        inspector.register(unrelated_exe, Some(&unrelated_sha), None);

        for (idx, (rule_id, domain)) in allow_rules.iter().enumerate() {
            store
                .upsert_rule(&AllowlistRuleRecord {
                    rule_id: (*rule_id).to_string(),
                    scope: RuleScope::NetworkAllow,
                    exe_path_pattern: ps_exe.to_string(),
                    sha256: Some(ps_sha.clone()),
                    signer_subject: None,
                    root_thumbprint: None,
                    allowed_target: Some((*domain).to_string()),
                    created_at_ms: base_ts - 10_000 + idx as i64,
                    created_by: "seed".to_string(),
                })
                .expect("seed NetworkAllow rule");
        }

        let engine = DaemonEngine::start_with_dependencies(
            store.clone(),
            SigmaEngine::default(),
            EarlyPruner::default(),
            DaemonConfig {
                pipe_name: unique_test_pipe_name(),
                preemptive_startup_executables: vec![ps_exe.to_string()],
                wfp_drop_dns_grace_ms: 2_000,
                ..DaemonConfig::default()
            },
            defense.clone(),
            notifier.clone(),
            inspector.clone(),
        );
        assert!(
            engine.has_active_wfp_filter(ps_exe, None, false),
            "pre-restricted powershell.exe must carry an app-wide preemptive WFP block at startup"
        );

        let ps_proc = ProcessIdentity::new(pid, unix_ms_to_filetime(base_ts - 5_000));
        let hp_before = engine.metrics().high_priority_processed;
        engine
            .sender()
            .send(SensorEvent::ProcessStart {
                identity: ps_proc,
                parent_pid: 4,
                exe_path: ps_exe.to_string(),
                command_line: format!("{ps_exe} -NoProfile"),
                user_sid: Some("S-1-5-21-1000".to_string()),
            })
            .await
            .expect("send ProcessStart");
        assert!(
            wait_until(1_000, || engine.metrics().high_priority_processed > hp_before).await,
            "ProcessStart must finish deterministically on the HighPriority lane"
        );
        assert!(
            engine.has_active_wfp_filter(ps_exe, None, false),
            "pre-restricted powershell.exe must keep its app-wide preemptive WFP block after ProcessStart"
        );

        Self {
            store,
            defense,
            notifier,
            inspector,
            engine,
            ps_exe,
            ps_sha,
            unrelated_exe,
            unrelated_sha,
            ps_proc,
        }
    }

    async fn send_promoted_dns(
        &self,
        query_name: &str,
        resolved_ips: Vec<IpAddr>,
        timestamp_ms: i64,
    ) {
        let ev = SensorEvent::DnsQuery {
            pid: self.ps_proc.pid,
            query_name: query_name.to_string(),
            query_type: 1,
            resolved_ips,
            timestamp_ms,
        };
        let classified = self.engine.classified_sender();
        assert!(
            classified.should_promote(&ev),
            "external DnsQuery for {query_name} must promote to HighPriority while domain rules exist"
        );
        let hp_before = self.engine.metrics().high_priority_processed;
        classified.send(ev).await.expect("send promoted DnsQuery");
        assert!(
            wait_until(1_000, || {
                self.engine.metrics().high_priority_processed > hp_before
            })
            .await,
            "promoted DnsQuery for {query_name} must finish HighPriority processing"
        );
    }

    async fn send_promoted_connect(
        &self,
        dst_ip: IpAddr,
        dst_port: u16,
        domain_hint: Option<&str>,
        timestamp_ms: i64,
    ) {
        let ev = SensorEvent::NetworkConnect {
            pid: self.ps_proc.pid,
            protocol: 6,
            dst_ip,
            dst_port,
            domain_hint: domain_hint.map(ToString::to_string),
            timestamp_ms,
        };
        let classified = self.engine.classified_sender();
        assert!(
            classified.should_promote(&ev),
            "external NetworkConnect to {dst_ip}:{dst_port} must promote to HighPriority"
        );
        let hp_before = self.engine.metrics().high_priority_processed;
        classified
            .send(ev)
            .await
            .expect("send promoted NetworkConnect");
        assert!(
            wait_until(1_000, || {
                self.engine.metrics().high_priority_processed > hp_before
            })
            .await,
            "promoted NetworkConnect to {dst_ip}:{dst_port} must finish HighPriority processing"
        );
    }

    async fn send_wfp_drop_and_barrier(
        &self,
        filter_id: u64,
        dst_ip: IpAddr,
        dst_port: u16,
        timestamp_ms: i64,
        barrier_label: &str,
    ) {
        assert!(self.engine.ingest_wfp_drop_event(WfpDropEvent {
            os_filter_id: filter_id,
            rule_handle: filter_id,
            exe_path: self.ps_exe.to_string(),
            protocol: 6,
            dst_ip,
            dst_port,
            timestamp_ms,
        }));
        let tel_before = self.engine.metrics().telemetry_processed;
        self.engine
            .sender()
            .send(SensorEvent::DnsQuery {
                pid: 99_999,
                query_name: format!("{barrier_label}.local"),
                query_type: 1,
                resolved_ips: Vec::new(),
                timestamp_ms: timestamp_ms + 1,
            })
            .await
            .expect("send Tier-3 telemetry barrier");
        assert!(
            wait_until(1_000, || {
                self.engine.metrics().telemetry_processed > tel_before
            })
            .await,
            "Tier-3 telemetry barrier `{barrier_label}` must confirm Tier-2b WfpDropEvent completed"
        );
    }

    fn upsert_unrelated_rule(&self, rule_id: &str, target_ip: IpAddr, created_at_ms: i64) {
        let report = self
            .engine
            .upsert_policy_rule(&AllowlistRuleRecord {
                rule_id: rule_id.to_string(),
                scope: RuleScope::NetworkAllow,
                exe_path_pattern: self.unrelated_exe.to_string(),
                sha256: Some(self.unrelated_sha.clone()),
                signer_subject: None,
                root_thumbprint: None,
                allowed_target: Some(target_ip.to_string()),
                created_at_ms,
                created_by: "test".to_string(),
            })
            .expect("upsert unrelated app rule");
        assert_eq!(
            report.failed, 0,
            "unrelated rule `{rule_id}` reconciliation must succeed without WFP failures"
        );
        assert!(
            self.engine
                .has_active_wfp_filter(self.unrelated_exe, Some(target_ip), true),
            "unrelated app rule `{rule_id}` must materialize its own WFP Permit"
        );
    }

    fn upsert_ps_block_domain(&self, rule_id: &str, domain: &str, created_at_ms: i64) {
        let report = self
            .engine
            .upsert_policy_rule(&AllowlistRuleRecord {
                rule_id: rule_id.to_string(),
                scope: RuleScope::NetworkBlock,
                exe_path_pattern: self.ps_exe.to_string(),
                sha256: Some(self.ps_sha.clone()),
                signer_subject: None,
                root_thumbprint: None,
                allowed_target: Some(domain.to_string()),
                created_at_ms,
                created_by: "test".to_string(),
            })
            .expect("upsert powershell NetworkBlock rule");
        assert_eq!(
            report.failed, 0,
            "powershell NetworkBlock rule `{rule_id}` reconciliation must succeed without WFP failures"
        );
    }

    async fn setup_shared_ip_and_migrate_api(
        &self,
        ip1: IpAddr,
        ip2: IpAddr,
        unrelated_ip: IpAddr,
        base_ts: i64,
        unrelated_rule_id: &str,
    ) {
        // 1. Unallowed `other.example` resolves to shared `ip1`.
        self.send_promoted_dns("other.example", vec![ip1], base_ts + 100)
            .await;
        assert!(
            !self.engine.has_active_wfp_filter(self.ps_exe, Some(ip1), true),
            "unallowed other.example alone must not materialize an IP Permit on {ip1}"
        );

        // 2. Allowed `api.example` resolves to the same shared `ip1`.
        self.send_promoted_dns("api.example", vec![ip1], base_ts + 200)
            .await;
        assert!(
            self.engine.has_active_wfp_filter(self.ps_exe, Some(ip1), true),
            "allowed api.example must materialize a DomainPolicy IP Permit on shared {ip1}"
        );

        // 3. `api.example` migrates to `ip2`.
        self.send_promoted_dns("api.example", vec![ip2], base_ts + 300)
            .await;
        assert!(
            self.engine.has_active_wfp_filter(self.ps_exe, Some(ip1), true),
            "cached old IP {ip1} Permit must stay active after api.example migrates to {ip2}"
        );
        assert!(
            self.engine.has_active_wfp_filter(self.ps_exe, Some(ip2), true),
            "new IP {ip2} Permit must be materialized after api.example migrates"
        );

        // 4. Unrelated rule save triggers full reconciliation.
        self.upsert_unrelated_rule(unrelated_rule_id, unrelated_ip, base_ts + 400);
        assert!(
            self.engine.has_active_wfp_filter(self.ps_exe, Some(ip1), true),
            "cached old IP {ip1} Permit must survive unrelated rule reconciliation"
        );
        assert!(
            self.engine.has_active_wfp_filter(self.ps_exe, Some(ip2), true),
            "migrated IP {ip2} Permit must survive unrelated rule reconciliation"
        );
        assert!(
            self.defense.removed_wfp().is_empty(),
            "no WFP filter should be revoked during shared-IP migration and unrelated reconcile"
        );
    }

    fn notified_alerts(&self) -> Vec<AlertRecord> {
        self.notifier
            .notified
            .lock()
            .expect("lock notified")
            .clone()
    }
}

/// `DAEMON-P3-48` (PR #5 Review #38 `PRRT_kwDOVyjVyM65e5kL` / `AUD-P3-01` E2E regression):
/// - Part 1: When a pre-restricted `powershell.exe` has `NetworkAllow(api.example)`, both
///   `other.example` and `api.example` resolve to shared `ip1`, `api.example` migrates to `ip2`,
///   and an unrelated app rule is saved via `upsert_policy_rule`, both `ip1` and `ip2` WFP Permits
///   remain active and subsequent `NetworkConnect(domain_hint: None)` plus a racing `WfpDropEvent`
///   against cached `ip1` succeed with 0 suspends, 0 false alerts, and `ip1` Permit intact.
/// - Part 2: Four isolated security boundaries from the exact same post-reconcile state:
///   (a) Adding `NetworkBlock(other.example)` while cohosted on `ip1` revokes `ip1` Permit
///       immediately (deny-overrides-allow) while keeping `ip2` Permit.
///   (b) Migrating `other.example` to `ip3` before adding `NetworkBlock(other.example)` preserves
///       `ip1` Permit and blocks `ip3`.
///   (c) Replacing the binary SHA-256 on disk (`MapBinaryInspector`) causes `NetworkConnect` to
///       cached `ip1` to revoke stale Permits, suspend the process, and emit a `Pending` alert
///       (`SEC_0001`).
///   (d) Deleting `NetworkAllow(api.example)` via `delete_policy_rule` revokes both `ip1` and `ip2`
///       Permits.
/// - Part 3: With two allowed domains (`keep.example` and `api.example`) plus unallowed
///   `other.example` sharing `ip1`, migrating `api.example` to `ip2` and adding
///   `NetworkBlock(api.example)` revokes `ip2` Permit while keeping `keep.example`'s `ip1` Permit.
#[tokio::test]
async fn daemon_p3_48_shared_ip_migrated_allow_permit_preservation_and_security_boundaries() {
    let ip1 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 148));
    let ip2 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 148));
    let ip3 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 149));
    let unrelated_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 148));
    let now_ms = current_unix_ms();
    let base_ts = now_ms - 4_000;

    // -------------------------------------------------------------------------
    // Part 1: Primary E2E regression (cached old IP connection + racing WfpDropEvent)
    // -------------------------------------------------------------------------
    {
        let h = P348Harness::start(9811, &[("R-ALLOW-API-P3-48", "api.example")], base_ts).await;
        h.setup_shared_ip_and_migrate_api(ip1, ip2, unrelated_ip, base_ts, "R-UNRELATED-P3-48-1")
            .await;

        // Cached old IP `ip1` NetworkConnect with `domain_hint: None` must pass cleanly.
        h.send_promoted_connect(ip1, 443, None, base_ts + 500).await;
        assert!(
            h.defense.suspends().is_empty(),
            "Part 1: cached old IP NetworkConnect must not suspend powershell.exe"
        );
        assert!(
            h.store.list_alerts(None, 20).expect("list alerts").is_empty(),
            "Part 1: cached old IP NetworkConnect must emit 0 alerts"
        );
        assert!(
            h.notified_alerts().is_empty(),
            "Part 1: cached old IP NetworkConnect must dispatch 0 notifications"
        );
        assert!(
            h.engine.has_active_wfp_filter(h.ps_exe, Some(ip1), true),
            "Part 1: ip1 Permit must remain active after NetworkConnect"
        );
        assert!(
            h.engine.has_active_wfp_filter(h.ps_exe, Some(ip2), true),
            "Part 1: ip2 Permit must remain active after NetworkConnect"
        );

        // Racing WfpDropEvent against cached old IP `ip1` must also pass without suspend/alert.
        h.send_wfp_drop_and_barrier(4801, ip1, 8443, base_ts + 550, "p3-48-part1-drop-barrier")
            .await;
        assert!(
            h.defense.suspends().is_empty(),
            "Part 1: racing WfpDropEvent on cached ip1 must produce 0 suspends"
        );
        assert!(
            h.store.list_alerts(None, 20).expect("list alerts").is_empty(),
            "Part 1: racing WfpDropEvent on cached ip1 must produce 0 false alerts"
        );
        assert!(
            h.notified_alerts().is_empty(),
            "Part 1: racing WfpDropEvent on cached ip1 must dispatch 0 notifications"
        );
        assert!(
            h.engine.has_active_wfp_filter(h.ps_exe, Some(ip1), true),
            "Part 1: ip1 Permit must remain intact after racing WfpDropEvent"
        );
        assert!(
            h.engine.has_active_wfp_filter(h.ps_exe, Some(ip2), true),
            "Part 1: ip2 Permit must remain intact after racing WfpDropEvent"
        );
        assert!(
            h.defense.removed_wfp().is_empty(),
            "Part 1: ip1 Permit must never have been revoked"
        );

        // Shutdown flushes any parked pending drops, verifying the drop was not silently deferred.
        h.engine
            .shutdown_and_flush()
            .await
            .expect("shutdown part 1");
        assert!(
            h.defense.suspends().is_empty(),
            "Part 1: 0 suspends must remain after shutdown_and_flush"
        );
        assert!(
            h.store.list_alerts(None, 20).expect("list alerts").is_empty(),
            "Part 1: 0 false alerts must remain after shutdown_and_flush"
        );
    }

    // -------------------------------------------------------------------------
    // Part 2(a): Security boundary — blocking cohosted `other.example` immediately
    // revokes `ip1` Permit (deny-overrides-allow) while preserving `ip2` Permit.
    // -------------------------------------------------------------------------
    {
        let h = P348Harness::start(9812, &[("R-ALLOW-API-P3-48", "api.example")], base_ts).await;
        h.setup_shared_ip_and_migrate_api(ip1, ip2, unrelated_ip, base_ts, "R-UNRELATED-P3-48-2A")
            .await;

        h.upsert_ps_block_domain("R-BLK-OTHER-P3-48-2A", "other.example", base_ts + 500);
        assert!(
            !h.engine.has_active_wfp_filter(h.ps_exe, Some(ip1), true),
            "Part 2(a): blocking cohosted other.example must immediately revoke ip1 Permit"
        );
        assert!(
            h.engine.has_active_wfp_filter(h.ps_exe, None, false),
            "Part 2(a): app-wide preemptive block must remain active so ip1 is blocked immediately"
        );
        assert!(
            h.engine.has_active_wfp_filter(h.ps_exe, Some(ip2), true),
            "Part 2(a): migrated api.example ip2 Permit must remain intact"
        );
        assert!(
            !h.engine.has_active_wfp_filter(h.ps_exe, Some(ip2), false),
            "Part 2(a): migrated api.example ip2 must not be blocked"
        );

        // Subsequent NetworkConnect to `ip1` must enforce the policy block (not live-permit allow).
        h.send_promoted_connect(ip1, 443, None, base_ts + 550).await;
        let alerts = h.store.list_alerts(None, 20).expect("list part 2a alerts");
        assert_eq!(
            alerts.len(),
            1,
            "Part 2(a): connecting to blocked shared ip1 must emit 1 policy-block alert (got {alerts:?})"
        );
        assert_eq!(alerts[0].rule_id, "LEDR-NET-POLICY-BLOCK");
        let ctx: serde_json::Value =
            serde_json::from_str(&alerts[0].context_json).expect("parse part 2a context_json");
        assert_eq!(
            ctx.get("matched_rule_id").and_then(serde_json::Value::as_str),
            Some("R-BLK-OTHER-P3-48-2A")
        );
        assert_eq!(
            ctx.get("domain_hint").and_then(serde_json::Value::as_str),
            Some("other.example")
        );
        assert_eq!(
            ctx.get("wfp_blocked").and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert!(
            !h.engine.has_active_wfp_filter(h.ps_exe, Some(ip1), true),
            "Part 2(a): ip1 Permit must stay revoked after connect"
        );
        assert!(
            h.engine.has_active_wfp_filter(h.ps_exe, Some(ip1), false),
            "Part 2(a): connecting to blocked shared ip1 must materialize IP-level DomainPolicy Block"
        );

        h.engine
            .shutdown_and_flush()
            .await
            .expect("shutdown part 2a");
    }

    // -------------------------------------------------------------------------
    // Part 2(b): Security boundary — after `other.example` also migrates to `ip3`,
    // adding `NetworkBlock(other.example)` blocks `ip3` without revoking `ip1` Permit.
    // -------------------------------------------------------------------------
    {
        let h = P348Harness::start(9813, &[("R-ALLOW-API-P3-48", "api.example")], base_ts).await;
        h.setup_shared_ip_and_migrate_api(ip1, ip2, unrelated_ip, base_ts, "R-UNRELATED-P3-48-2B")
            .await;

        h.send_promoted_dns("other.example", vec![ip3], base_ts + 500)
            .await;
        assert!(
            h.engine.has_active_wfp_filter(h.ps_exe, Some(ip1), true),
            "Part 2(b): ip1 Permit must remain active after other.example migrates to ip3"
        );
        assert!(
            !h.engine.has_active_wfp_filter(h.ps_exe, Some(ip3), true),
            "Part 2(b): unallowed other.example migrating to ip3 must not create an ip3 Permit"
        );

        h.upsert_ps_block_domain("R-BLK-OTHER-P3-48-2B", "other.example", base_ts + 550);
        assert!(
            h.engine.has_active_wfp_filter(h.ps_exe, Some(ip1), true),
            "Part 2(b): ip1 Permit must remain active when migrated other.example is later blocked"
        );
        assert!(
            !h.engine.has_active_wfp_filter(h.ps_exe, Some(ip1), false),
            "Part 2(b): ip1 must not receive a Block after other.example migrated away"
        );
        assert!(
            h.engine.has_active_wfp_filter(h.ps_exe, Some(ip2), true),
            "Part 2(b): ip2 Permit must remain active"
        );
        assert!(
            !h.engine.has_active_wfp_filter(h.ps_exe, Some(ip3), true),
            "Part 2(b): ip3 must not have a Permit"
        );
        assert!(
            h.defense.removed_wfp().is_empty(),
            "Part 2(b): ip1 Permit must not be removed during selective pruning or later block"
        );

        // Cached old IP `ip1` connection still passes with 0 suspends and 0 alerts.
        h.send_promoted_connect(ip1, 443, None, base_ts + 600).await;
        assert!(
            h.defense.suspends().is_empty(),
            "Part 2(b): cached ip1 connection must not suspend"
        );
        assert!(
            h.store.list_alerts(None, 20).expect("list alerts").is_empty(),
            "Part 2(b): cached ip1 connection must emit 0 alerts"
        );
        assert!(
            h.engine.has_active_wfp_filter(h.ps_exe, Some(ip1), true),
            "Part 2(b): ip1 Permit must stay active after cached ip1 connection"
        );

        // Connecting to `other.example`'s new IP `ip3` enforces the block rule without affecting `ip1`.
        h.send_promoted_connect(ip3, 443, None, base_ts + 650).await;
        let alerts = h.store.list_alerts(None, 20).expect("list part 2b alerts");
        assert_eq!(
            alerts.len(),
            1,
            "Part 2(b): connecting to migrated other.example ip3 must emit 1 policy-block alert (got {alerts:?})"
        );
        assert_eq!(alerts[0].rule_id, "LEDR-NET-POLICY-BLOCK");
        let ctx: serde_json::Value =
            serde_json::from_str(&alerts[0].context_json).expect("parse part 2b context_json");
        assert_eq!(
            ctx.get("matched_rule_id").and_then(serde_json::Value::as_str),
            Some("R-BLK-OTHER-P3-48-2B")
        );
        assert_eq!(
            ctx.get("domain_hint").and_then(serde_json::Value::as_str),
            Some("other.example")
        );
        assert!(
            h.engine.has_active_wfp_filter(h.ps_exe, Some(ip3), false),
            "Part 2(b): connecting to ip3 must materialize DomainPolicy Block on ip3"
        );
        assert!(
            h.engine.has_active_wfp_filter(h.ps_exe, Some(ip1), true),
            "Part 2(b): ip1 Permit must remain active after blocking ip3"
        );

        h.engine
            .shutdown_and_flush()
            .await
            .expect("shutdown part 2b");
    }

    // -------------------------------------------------------------------------
    // Part 2(c): Security boundary (`SEC_0001`) — replacing binary SHA-256 on disk
    // before connecting to cached `ip1` revokes stale Permits, suspends, and alerts.
    // -------------------------------------------------------------------------
    {
        let h = P348Harness::start(9814, &[("R-ALLOW-API-P3-48", "api.example")], base_ts).await;
        h.setup_shared_ip_and_migrate_api(ip1, ip2, unrelated_ip, base_ts, "R-UNRELATED-P3-48-2C")
            .await;

        let tampered_sha = "f".repeat(64);
        h.inspector.register(h.ps_exe, Some(&tampered_sha), None);

        h.send_promoted_connect(ip1, 443, None, base_ts + 500).await;
        assert!(
            !h.engine.has_active_wfp_filter(h.ps_exe, Some(ip1), true),
            "Part 2(c): stale ip1 Permit must be revoked on binary SHA-256 mismatch (SEC_0001)"
        );
        assert!(
            !h.engine.has_active_wfp_filter(h.ps_exe, Some(ip2), true),
            "Part 2(c): stale ip2 Permit must also be revoked on binary SHA-256 mismatch (SEC_0001)"
        );
        assert!(
            h.engine.has_active_wfp_filter(h.ps_exe, None, false),
            "Part 2(c): app-wide preemptive WFP block must remain enforced"
        );
        assert_eq!(
            h.defense.suspends(),
            vec![h.ps_proc],
            "Part 2(c): tampered process connecting to cached ip1 must be suspended (SEC_0001)"
        );
        let alerts = h
            .store
            .list_alerts(Some(AlertStatus::Pending), 20)
            .expect("list part 2c pending alerts");
        assert_eq!(
            alerts.len(),
            1,
            "Part 2(c): tampered process connecting to cached ip1 must emit 1 Pending alert (got {alerts:?})"
        );
        assert_eq!(alerts[0].rule_id, "LEDR-NET-SCRIPT-INTERPRETER");
        assert!(
            alerts[0].process_suspended,
            "Part 2(c): alert must record confirmed process suspension"
        );
        let ctx: serde_json::Value =
            serde_json::from_str(&alerts[0].context_json).expect("parse part 2c context_json");
        assert_eq!(
            ctx.get("dst_ip").and_then(serde_json::Value::as_str),
            Some(ip1.to_string().as_str())
        );
        assert_eq!(
            ctx.get("sha256").and_then(serde_json::Value::as_str),
            Some(tampered_sha.as_str())
        );
        assert_eq!(
            ctx.get("wfp_blocked").and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert_eq!(
            h.notified_alerts().len(),
            1,
            "Part 2(c): containment alert must be dispatched to notifier"
        );

        h.engine
            .shutdown_and_flush()
            .await
            .expect("shutdown part 2c");
    }

    // -------------------------------------------------------------------------
    // Part 2(d): Security boundary — deleting `NetworkAllow(api.example)` revokes
    // both `ip1` and `ip2` Permits while leaving unrelated rules intact.
    // -------------------------------------------------------------------------
    {
        let h = P348Harness::start(9815, &[("R-ALLOW-API-P3-48", "api.example")], base_ts).await;
        h.setup_shared_ip_and_migrate_api(ip1, ip2, unrelated_ip, base_ts, "R-UNRELATED-P3-48-2D")
            .await;

        let (deleted, report) = h
            .engine
            .delete_policy_rule("R-ALLOW-API-P3-48")
            .expect("delete NetworkAllow(api.example)");
        assert!(deleted, "Part 2(d): delete_policy_rule must report deletion");
        assert_eq!(
            report.failed, 0,
            "Part 2(d): delete_policy_rule reconciliation must succeed without WFP failures"
        );
        assert!(
            !h.engine.has_active_wfp_filter(h.ps_exe, Some(ip1), true),
            "Part 2(d): deleting api.example allow rule must revoke ip1 Permit"
        );
        assert!(
            !h.engine.has_active_wfp_filter(h.ps_exe, Some(ip2), true),
            "Part 2(d): deleting api.example allow rule must revoke ip2 Permit"
        );
        assert!(
            h.engine.has_active_wfp_filter(h.ps_exe, None, false),
            "Part 2(d): app-wide preemptive block must remain active after allow deletion"
        );
        assert!(
            h.engine
                .has_active_wfp_filter(h.unrelated_exe, Some(unrelated_ip), true),
            "Part 2(d): unrelated app rule Permit must remain untouched"
        );

        // Subsequent NetworkConnect to `ip1` must now suspend and alert.
        h.send_promoted_connect(ip1, 443, None, base_ts + 500).await;
        assert_eq!(
            h.defense.suspends(),
            vec![h.ps_proc],
            "Part 2(d): connecting to ip1 after allow deletion must suspend powershell.exe"
        );
        let alerts = h
            .store
            .list_alerts(Some(AlertStatus::Pending), 20)
            .expect("list part 2d pending alerts");
        assert_eq!(
            alerts.len(),
            1,
            "Part 2(d): connecting to ip1 after allow deletion must emit 1 Pending alert"
        );
        assert_eq!(alerts[0].rule_id, "LEDR-NET-SCRIPT-INTERPRETER");
        assert!(alerts[0].process_suspended);

        h.engine
            .shutdown_and_flush()
            .await
            .expect("shutdown part 2d");
    }

    // -------------------------------------------------------------------------
    // Part 3: Multi-allowed shared IP (`keep.example` + `api.example` + unallowed
    // `other.example` on `ip1`): migrating `api.example` to `ip2` and then blocking
    // `api.example` revokes `ip2` Permit while preserving `keep.example`'s `ip1` Permit.
    // -------------------------------------------------------------------------
    {
        let h = P348Harness::start(
            9816,
            &[
                ("R-ALLOW-KEEP-P3-48", "keep.example"),
                ("R-ALLOW-API-P3-48", "api.example"),
            ],
            base_ts,
        )
        .await;

        h.send_promoted_dns("other.example", vec![ip1], base_ts + 100)
            .await;
        assert!(
            !h.engine.has_active_wfp_filter(h.ps_exe, Some(ip1), true),
            "Part 3: unallowed other.example alone must not create an ip1 Permit"
        );
        h.send_promoted_dns("keep.example", vec![ip1], base_ts + 200)
            .await;
        assert!(
            h.engine.has_active_wfp_filter(h.ps_exe, Some(ip1), true),
            "Part 3: keep.example must materialize ip1 Permit"
        );
        h.send_promoted_dns("api.example", vec![ip1], base_ts + 300)
            .await;
        assert!(
            h.engine.has_active_wfp_filter(h.ps_exe, Some(ip1), true),
            "Part 3: api.example sharing ip1 must keep ip1 Permit active"
        );

        // Migrate `api.example` away to `ip2`: `keep.example` sustains `ip1` Permit so
        // `api.example` is pruned from `ip1`'s Permit hints while `ip2` receives its Permit.
        h.send_promoted_dns("api.example", vec![ip2], base_ts + 400)
            .await;
        assert!(
            h.engine.has_active_wfp_filter(h.ps_exe, Some(ip1), true),
            "Part 3: ip1 Permit must stay active for keep.example after api.example migrates"
        );
        assert!(
            h.engine.has_active_wfp_filter(h.ps_exe, Some(ip2), true),
            "Part 3: ip2 Permit must be materialized for migrated api.example"
        );

        // Block `api.example`: must revoke `ip2` Permit while leaving `keep.example`'s `ip1`
        // Permit untouched.
        h.upsert_ps_block_domain("R-BLK-API-P3-48-3", "api.example", base_ts + 500);
        assert!(
            h.engine.has_active_wfp_filter(h.ps_exe, Some(ip1), true),
            "Part 3: keep.example ip1 Permit must remain active after blocking migrated api.example"
        );
        assert!(
            !h.engine.has_active_wfp_filter(h.ps_exe, Some(ip1), false),
            "Part 3: ip1 must not be blocked after api.example migrated away"
        );
        assert!(
            !h.engine.has_active_wfp_filter(h.ps_exe, Some(ip2), true),
            "Part 3: migrated api.example ip2 Permit must be revoked by NetworkBlock(api.example)"
        );
        assert!(
            h.engine.has_active_wfp_filter(h.ps_exe, None, false),
            "Part 3: app-wide preemptive block must remain active to cover revoked ip2"
        );

        // Verify E2E traffic and racing WfpDropEvent to `ip1` continue cleanly with 0 suspends / 0 alerts.
        h.send_promoted_connect(ip1, 443, None, base_ts + 550).await;
        h.send_wfp_drop_and_barrier(4802, ip1, 8443, base_ts + 600, "p3-48-part3-drop-barrier")
            .await;
        assert!(
            h.defense.suspends().is_empty(),
            "Part 3: keep.example traffic on ip1 must produce 0 suspends"
        );
        assert!(
            h.store.list_alerts(None, 20).expect("list alerts").is_empty(),
            "Part 3: keep.example traffic on ip1 must produce 0 false alerts"
        );
        assert!(
            h.engine.has_active_wfp_filter(h.ps_exe, Some(ip1), true),
            "Part 3: ip1 Permit must stay active after E2E traffic and drop triage"
        );

        // Verify connecting to migrated `api.example`'s `ip2` enforces `NetworkBlock(api.example)`
        // without disturbing `keep.example`'s `ip1` Permit.
        h.send_promoted_connect(ip2, 443, None, base_ts + 650).await;
        let alerts = h.store.list_alerts(None, 20).expect("list part 3 alerts");
        assert_eq!(
            alerts.len(),
            1,
            "Part 3: connecting to blocked migrated api.example ip2 must emit 1 policy-block alert (got {alerts:?})"
        );
        assert_eq!(alerts[0].rule_id, "LEDR-NET-POLICY-BLOCK");
        let ctx: serde_json::Value =
            serde_json::from_str(&alerts[0].context_json).expect("parse part 3 context_json");
        assert_eq!(
            ctx.get("matched_rule_id").and_then(serde_json::Value::as_str),
            Some("R-BLK-API-P3-48-3")
        );
        assert_eq!(
            ctx.get("domain_hint").and_then(serde_json::Value::as_str),
            Some("api.example")
        );
        assert!(
            h.engine.has_active_wfp_filter(h.ps_exe, Some(ip2), false),
            "Part 3: connecting to blocked api.example ip2 must materialize DomainPolicy Block on ip2"
        );
        assert!(
            h.engine.has_active_wfp_filter(h.ps_exe, Some(ip1), true),
            "Part 3: keep.example ip1 Permit must stay active after blocking ip2"
        );

        h.engine
            .shutdown_and_flush()
            .await
            .expect("shutdown part 3");
        assert!(
            h.defense.suspends().is_empty(),
            "Part 3: 0 suspends must remain after shutdown_and_flush"
        );
    }
}

#[tokio::test]
async fn daemon_p3_49_self_process_outbound_exclusion_boundaries() {
    let self_pid = std::process::id();
    let other_pid = if self_pid == u32::MAX {
        self_pid - 1
    } else {
        self_pid + 1
    };
    let raw_self_exe = std::env::current_exe()
        .expect("resolve current_exe")
        .to_string_lossy()
        .into_owned();
    let bare_self_exe = raw_self_exe
        .strip_prefix(r"\\?\")
        .unwrap_or(&raw_self_exe)
        .to_string();

    // Part 1: Self process with exact path, extended Win32 (`\\?\`), NT (`\??\`), and case/slash
    // variants must be excluded from outbound alerts, suspends, and WFP filters.
    let self_variants = vec![
        ("exact", raw_self_exe.clone()),
        ("win32_extended", format!(r"\\?\{bare_self_exe}")),
        ("nt_prefix", format!(r"\??\{bare_self_exe}")),
        (
            "nt_mixed_slash",
            format!(r"\??/{}", bare_self_exe.replace('\\', "/")),
        ),
        (
            "case_and_slash",
            bare_self_exe.to_uppercase().replace('\\', "/"),
        ),
    ];

    for (label, exe_variant) in self_variants {
        let store = LedrStore::open_in_memory().expect("open store");
        let defense = Arc::new(MockWfpDefense::new());
        let notifier = Arc::new(MockNotifier::default());
        let inspector = Arc::new(MapBinaryInspector::default());
        let mut cfg = default_test_config();
        cfg.outbound_firewall_enabled = true;
        cfg.outbound_enforcement_mode = ledr_daemon::OutboundEnforcementMode::Enforce;

        let engine = start_test_engine(
            store.clone(),
            cfg,
            defense.clone(),
            notifier.clone(),
            inspector,
        );
        let sender = engine.sender();
        let classified = engine.classified_sender();
        let base_ts = current_unix_ms();

        send_process_start(
            &sender,
            ProcessIdentity::new(self_pid, unix_ms_to_filetime(base_ts)),
            &exe_variant,
        )
        .await;
        assert!(
            wait_until(2000, || engine.metrics().high_priority_processed >= 1).await,
            "self variant `{label}` ProcessStart should be processed"
        );

        // Via `classified_sender`, self_pid must stay on Telemetry lane (not promoted).
        classified
            .send(SensorEvent::NetworkConnect {
                pid: self_pid,
                protocol: 6,
                dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
                dst_port: 443,
                domain_hint: Some("ctldl.windowsupdate.com".to_string()),
                timestamp_ms: base_ts + 50,
            })
            .await
            .expect("send self NetworkConnect via classified_sender");
        assert!(
            wait_until(2000, || engine.metrics().telemetry_processed >= 1).await,
            "self variant `{label}` NetworkConnect should remain on telemetry lane"
        );

        // Also test direct high-priority submission to confirm `handle_network_connect` itself
        // excludes the self process regardless of lane classification.
        sender
            .send_high_priority(SensorEvent::NetworkConnect {
                pid: self_pid,
                protocol: 6,
                dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 11)),
                dst_port: 80,
                domain_hint: None,
                timestamp_ms: base_ts + 60,
            })
            .await
            .expect("send self NetworkConnect via high-priority lane");
        assert!(
            wait_until(2000, || engine.metrics().high_priority_processed >= 2).await,
            "self variant `{label}` direct HP NetworkConnect should be processed"
        );

        assert!(
            store.list_alerts(None, 20).expect("list alerts").is_empty(),
            "self variant `{label}` must emit 0 outbound alerts"
        );
        assert!(
            defense.suspends().is_empty(),
            "self variant `{label}` must not suspend self process"
        );
        assert!(
            defense.added_wfp().is_empty(),
            "self variant `{label}` must not install WFP rules for self process"
        );

        engine.shutdown_and_flush().await.expect("shutdown engine");
    }

    // Part 2: Non-matching boundaries must NOT be excluded:
    // (a) Same PID as daemon but different executable path (`C:\Temp\fake\ledr-daemon.exe`).
    {
        let store = LedrStore::open_in_memory().expect("open store");
        let defense = Arc::new(MockWfpDefense::new());
        let notifier = Arc::new(MockNotifier::default());
        let inspector = Arc::new(MapBinaryInspector::default());
        let mut cfg = default_test_config();
        cfg.outbound_firewall_enabled = true;
        cfg.outbound_enforcement_mode = ledr_daemon::OutboundEnforcementMode::Enforce;

        let engine = start_test_engine(
            store.clone(),
            cfg,
            defense.clone(),
            notifier,
            inspector,
        );
        let sender = engine.sender();
        let classified = engine.classified_sender();
        let base_ts = current_unix_ms();

        send_process_start(
            &sender,
            ProcessIdentity::new(self_pid, unix_ms_to_filetime(base_ts)),
            r"C:\Temp\fake\ledr-daemon.exe",
        )
        .await;
        assert!(wait_until(2000, || engine.metrics().high_priority_processed >= 1).await);

        classified
            .send(SensorEvent::NetworkConnect {
                pid: self_pid,
                protocol: 6,
                dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
                dst_port: 443,
                domain_hint: None,
                timestamp_ms: base_ts + 50,
            })
            .await
            .expect("send fake-path NetworkConnect");
        assert!(
            wait_until(2000, || engine.metrics().high_priority_processed >= 2).await,
            "(self_pid, fake exe) must be promoted to high-priority lane and evaluated"
        );
        let alerts = store.list_alerts(None, 20).expect("list alerts");
        assert!(
            !alerts.is_empty(),
            "(self_pid, fake exe) must NOT be excluded from outbound alerting"
        );
        assert!(
            !defense.suspends().is_empty(),
            "(self_pid, fake exe) must still be suspended in Enforce mode"
        );

        engine.shutdown_and_flush().await.expect("shutdown engine");
    }

    // (b) Different PID running the same executable path (`current_exe`).
    {
        let store = LedrStore::open_in_memory().expect("open store");
        let defense = Arc::new(MockWfpDefense::new());
        let notifier = Arc::new(MockNotifier::default());
        let inspector = Arc::new(MapBinaryInspector::default());
        let mut cfg = default_test_config();
        cfg.outbound_firewall_enabled = true;
        cfg.outbound_enforcement_mode = ledr_daemon::OutboundEnforcementMode::Enforce;

        let engine = start_test_engine(
            store.clone(),
            cfg,
            defense.clone(),
            notifier,
            inspector,
        );
        let sender = engine.sender();
        let classified = engine.classified_sender();
        let base_ts = current_unix_ms();

        send_process_start(
            &sender,
            ProcessIdentity::new(other_pid, unix_ms_to_filetime(base_ts)),
            &bare_self_exe,
        )
        .await;
        assert!(wait_until(2000, || engine.metrics().high_priority_processed >= 1).await);

        classified
            .send(SensorEvent::NetworkConnect {
                pid: other_pid,
                protocol: 6,
                dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 21)),
                dst_port: 443,
                domain_hint: None,
                timestamp_ms: base_ts + 50,
            })
            .await
            .expect("send other_pid NetworkConnect");
        assert!(
            wait_until(2000, || engine.metrics().high_priority_processed >= 2).await,
            "(other_pid, current_exe) must be promoted and evaluated"
        );
        let alerts = store.list_alerts(None, 20).expect("list alerts");
        assert!(
            !alerts.is_empty(),
            "(other_pid, current_exe) must NOT be excluded from outbound alerting"
        );
        assert!(
            !defense.suspends().is_empty(),
            "(other_pid, current_exe) must still be suspended in Enforce mode"
        );

        engine.shutdown_and_flush().await.expect("shutdown engine");
    }

    // (c) Empty executable path on `self_pid` must NOT be treated as self-process (clears
    // `outbound_classifier` protected marker so subsequent external connect promotes to HP).
    {
        let store = LedrStore::open_in_memory().expect("open store");
        let defense = Arc::new(MockWfpDefense::new());
        let notifier = Arc::new(MockNotifier::default());
        let inspector = Arc::new(MapBinaryInspector::default());
        let mut cfg = default_test_config();
        cfg.outbound_firewall_enabled = true;
        cfg.outbound_enforcement_mode = ledr_daemon::OutboundEnforcementMode::Enforce;

        let engine = start_test_engine(store, cfg, defense, notifier, inspector);
        let sender = engine.sender();
        let classified = engine.classified_sender();
        let base_ts = current_unix_ms();

        send_process_start(
            &sender,
            ProcessIdentity::new(self_pid, unix_ms_to_filetime(base_ts)),
            "   ",
        )
        .await;
        assert!(wait_until(2000, || engine.metrics().high_priority_processed >= 1).await);

        classified
            .send(SensorEvent::NetworkConnect {
                pid: self_pid,
                protocol: 6,
                dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 22)),
                dst_port: 443,
                domain_hint: None,
                timestamp_ms: base_ts + 50,
            })
            .await
            .expect("send empty-exe NetworkConnect");
        assert!(
            wait_until(2000, || engine.metrics().high_priority_processed >= 2).await,
            "(self_pid, empty exe_path) must NOT remain marked as protected self process"
        );
        assert_eq!(engine.metrics().telemetry_processed, 0);

        engine.shutdown_and_flush().await.expect("shutdown engine");
    }
}

#[tokio::test]
async fn daemon_p3_50_self_process_skips_dns_wfp_prematerialization() {
    let self_pid = std::process::id();
    let other_pid = if self_pid == u32::MAX {
        self_pid - 1
    } else {
        self_pid + 1
    };
    let raw_self_exe = std::env::current_exe()
        .expect("resolve current_exe")
        .to_string_lossy()
        .into_owned();
    let bare_self_exe = raw_self_exe
        .strip_prefix(r"\\?\")
        .unwrap_or(&raw_self_exe)
        .to_string();

    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());
    let mut cfg = default_test_config();
    cfg.outbound_firewall_enabled = true;
    cfg.outbound_enforcement_mode = ledr_daemon::OutboundEnforcementMode::Enforce;

    let engine = start_test_engine(store, cfg, defense.clone(), notifier, inspector);

    // Install a wildcard domain-scoped NetworkBlock rule so any non-exempt process resolving
    // `blocked.example.invalid` triggers DNS WFP filter pre-materialization.
    let block_rule = AllowlistRuleRecord {
        rule_id: "rule-wildcard-domain-block-self-check".to_string(),
        scope: RuleScope::NetworkBlock,
        exe_path_pattern: "*".to_string(),
        signer_subject: None,
        root_thumbprint: None,
        sha256: None,
        allowed_target: Some("blocked.example.invalid".to_string()),
        created_at_ms: current_unix_ms(),
        created_by: "test".to_string(),
    };
    engine
        .upsert_policy_rule(&block_rule)
        .expect("upsert wildcard domain block rule");

    let sender = engine.sender();
    let base_ts = current_unix_ms();

    // 1. Self process resolving the blocked domain must NOT pre-materialize a WFP block filter.
    send_process_start(
        &sender,
        ProcessIdentity::new(self_pid, unix_ms_to_filetime(base_ts)),
        &bare_self_exe,
    )
    .await;
    assert!(wait_until(2000, || engine.metrics().high_priority_processed >= 1).await);

    sender
        .send_high_priority(SensorEvent::DnsQuery {
            pid: self_pid,
            query_name: "blocked.example.invalid".to_string(),
            query_type: 1,
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77))],
            timestamp_ms: base_ts + 25,
        })
        .await
        .expect("send self DnsQuery");
    assert!(wait_until(2000, || engine.metrics().high_priority_processed >= 2).await);
    assert!(
        defense.added_wfp().is_empty(),
        "self-process DnsQuery must not pre-materialize WFP block filters: {:?}",
        defense.added_wfp()
    );

    // 2. Non-self PID running the same binary resolving the same domain MUST pre-materialize it.
    send_process_start(
        &sender,
        ProcessIdentity::new(other_pid, unix_ms_to_filetime(base_ts + 30)),
        &bare_self_exe,
    )
    .await;
    assert!(wait_until(2000, || engine.metrics().high_priority_processed >= 3).await);

    sender
        .send_high_priority(SensorEvent::DnsQuery {
            pid: other_pid,
            query_name: "blocked.example.invalid".to_string(),
            query_type: 1,
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77))],
            timestamp_ms: base_ts + 40,
        })
        .await
        .expect("send other_pid DnsQuery");
    assert!(wait_until(2000, || engine.metrics().high_priority_processed >= 4).await);
    assert!(
        defense
            .added_wfp()
            .iter()
            .any(|f| !f.allow && f.remote_ip == Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77)))),
        "non-self PID DnsQuery must still pre-materialize domain WFP block filter: {:?}",
        defense.added_wfp()
    );

    engine.shutdown_and_flush().await.expect("shutdown engine");
}

/// `DAEMON-P3-53` (`FU-E2E-05`, `E2E-P3-01` preservation):
/// - Part A: Single malicious process connecting to an IPv4 literal under
///   `wfp_drop_attribution_grace_ms` with repeated `WfpDropEvent` retries (`> 250 ms` apart)
///   deduplicates pending entries without extending the deadline and suspends the process once the
///   grace expires (`Pending` alert bound to `process_instance_id`).
/// - Part B: Single process with a domain `NetworkAllow` rule whose own `DnsQuery` arrives during
///   `AttributionGrace` re-evaluates via `select_outbound_decision_for_domains`, installs a
///   temporary WFP Permit, and emits 0 suspends / 0 alerts.
/// - Part C: Multi-candidate 60 s DNS freshness symmetry keeps stale (> 60 s) allowed DNS from
///   emitting an early Permit and produces an `app_level_ambiguous` alert (`0` suspends).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_p3_53_single_process_freeze_retry_dedup_and_grace_own_dns_allow() {
    let tool_exe = r"C:\Users\alice\Downloads\p353_tool.exe";

    // Part A: Single malicious process + retries > 250 ms apart do not extend grace deadline.
    {
        let store = LedrStore::open_in_memory().expect("open store");
        let defense = Arc::new(MockWfpDefense::new());
        let notifier = Arc::new(MockNotifier::default());
        let inspector = Arc::new(MapBinaryInspector::default());

        let engine = start_test_engine(
            store.clone(),
            DaemonConfig {
                pipe_name: unique_test_pipe_name(),
                outbound_firewall_enabled: true,
                wfp_drop_dns_grace_ms: 0,
                wfp_drop_attribution_grace_ms: 500,
                wfp_drop_live_sibling_os_check: false,
                ..DaemonConfig::default()
            },
            defense.clone(),
            notifier,
            inspector,
        );

        let now_ms = current_unix_ms();
        let proc_id = ProcessIdentity::new(9911, unix_ms_to_filetime(now_ms - 500));
        let inst_id = proc_id.instance_id();
        send_process_start(&engine.sender(), proc_id, tool_exe).await;
        assert!(wait_until(1_000, || engine.metrics().high_priority_processed >= 1).await);

        let dst_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 91));
        assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
            os_filter_id: 1,
            rule_handle: 1,
            exe_path: tool_exe.to_string(),
            protocol: 6,
            dst_ip,
            dst_port: 443,
            timestamp_ms: now_ms,
        }));
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(
            defense.suspends().is_empty(),
            "single candidate should wait out initial attribution grace"
        );

        // Retry past 250ms transport dedup window while the parked drop is still pending.
        tokio::time::sleep(Duration::from_millis(240)).await;
        assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
            os_filter_id: 1,
            rule_handle: 1,
            exe_path: tool_exe.to_string(),
            protocol: 6,
            dst_ip,
            dst_port: 443,
            timestamp_ms: now_ms + 280,
        }));
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(
            defense.suspends().is_empty(),
            "retry at +280ms must not bypass remaining grace prematurely"
        );

        // If retry had extended the 500ms deadline to 280+500=780ms, waiting 350ms from now (~670ms)
        // would time out. Without extension, original 500ms deadline fires around ~220ms from now.
        assert!(
            wait_until(380, || defense.suspends() == vec![proc_id]).await,
            "pending dedup must preserve original deadline and suspend single malicious process promptly"
        );
        let alerts = store.list_alerts(Some(AlertStatus::Pending), 10).expect("alerts");
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].process_suspended);
        assert_eq!(alerts[0].process_instance_id.as_deref(), Some(inst_id.as_str()));

        engine.shutdown_and_flush().await.expect("shutdown Part A");
    }

    // Part B: Own allowed DnsQuery arriving during AttributionGrace re-evaluates to AllowedByRule.
    {
        let store = LedrStore::open_in_memory().expect("open store");
        let defense = Arc::new(MockWfpDefense::new());
        let notifier = Arc::new(MockNotifier::default());
        let inspector = Arc::new(MapBinaryInspector::default());
        let hash = "d".repeat(64);
        inspector.register(tool_exe, Some(&hash), None);

        let now_ms = current_unix_ms();
        store
            .upsert_rule(&AllowlistRuleRecord {
                rule_id: "R-P3-53-ALLOW-DOMAIN".to_string(),
                scope: RuleScope::NetworkAllow,
                exe_path_pattern: tool_exe.to_string(),
                sha256: Some(hash),
                signer_subject: None,
                root_thumbprint: None,
                allowed_target: Some("allowed.example.invalid".to_string()),
                created_at_ms: now_ms,
                created_by: "test".to_string(),
            })
            .expect("seed NetworkAllow domain rule");

        let engine = start_test_engine(
            store.clone(),
            DaemonConfig {
                pipe_name: unique_test_pipe_name(),
                outbound_firewall_enabled: true,
                wfp_drop_dns_grace_ms: 0,
                wfp_drop_attribution_grace_ms: 350,
                wfp_drop_live_sibling_os_check: false,
                ..DaemonConfig::default()
            },
            defense.clone(),
            notifier,
            inspector,
        );

        let proc_id = ProcessIdentity::new(9912, unix_ms_to_filetime(now_ms - 500));
        send_process_start(&engine.sender(), proc_id, tool_exe).await;
        assert!(wait_until(1_000, || engine.metrics().high_priority_processed >= 1).await);

        let dst_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 92));
        assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
            os_filter_id: 2,
            rule_handle: 2,
            exe_path: tool_exe.to_string(),
            protocol: 6,
            dst_ip,
            dst_port: 443,
            timestamp_ms: now_ms + 10,
        }));
        tokio::time::sleep(Duration::from_millis(40)).await;

        engine
            .sender()
            .send_high_priority(SensorEvent::DnsQuery {
                pid: proc_id.pid,
                query_name: "allowed.example.invalid".to_string(),
                query_type: 1,
                resolved_ips: vec![dst_ip],
                timestamp_ms: now_ms + 30,
            })
            .await
            .expect("send own allowed DnsQuery");

        assert!(
            wait_until(1_000, || {
                engine.has_active_wfp_filter(tool_exe, Some(dst_ip), true)
            })
            .await,
            "own allowed DnsQuery during AttributionGrace must authorize Permit via select_outbound_decision_for_domains"
        );
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(
            defense.suspends().is_empty(),
            "allowed domain during AttributionGrace must produce 0 suspends"
        );
        assert!(
            store.list_alerts(None, 10).expect("alerts").is_empty(),
            "allowed domain during AttributionGrace must produce 0 alerts"
        );

        engine.shutdown_and_flush().await.expect("shutdown Part B");
    }

    // Part C: Multi-candidate 60 s DNS freshness symmetry rejects stale (> 60 s) allowed DNS.
    {
        let store = LedrStore::open_in_memory().expect("open store");
        let defense = Arc::new(MockWfpDefense::new());
        let notifier = Arc::new(MockNotifier::default());
        let inspector = Arc::new(MapBinaryInspector::default());
        let hash = "e".repeat(64);
        inspector.register(tool_exe, Some(&hash), None);

        let now_ms = current_unix_ms();
        store
            .upsert_rule(&AllowlistRuleRecord {
                rule_id: "R-P3-53-ALLOW-STALE".to_string(),
                scope: RuleScope::NetworkAllow,
                exe_path_pattern: tool_exe.to_string(),
                sha256: Some(hash),
                signer_subject: None,
                root_thumbprint: None,
                allowed_target: Some("stale.example.invalid".to_string()),
                created_at_ms: now_ms,
                created_by: "test".to_string(),
            })
            .expect("seed allow rule");

        let engine = start_test_engine(
            store.clone(),
            DaemonConfig {
                pipe_name: unique_test_pipe_name(),
                outbound_firewall_enabled: true,
                wfp_drop_dns_grace_ms: 150,
                wfp_drop_attribution_grace_ms: 0,
                wfp_drop_live_sibling_os_check: false,
                ..DaemonConfig::default()
            },
            defense.clone(),
            notifier,
            inspector,
        );

        let p1 = ProcessIdentity::new(9913, unix_ms_to_filetime(now_ms - 120_000));
        let p2 = ProcessIdentity::new(9914, unix_ms_to_filetime(now_ms - 5_000));
        send_process_start(&engine.sender(), p1, tool_exe).await;
        send_process_start(&engine.sender(), p2, tool_exe).await;
        assert!(wait_until(1_000, || engine.metrics().high_priority_processed >= 2).await);

        let dst_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 93));
        // Stale DNS resolution (> 60_000 ms before drop timestamp) on p1.
        engine
            .sender()
            .send_high_priority(SensorEvent::DnsQuery {
                pid: p1.pid,
                query_name: "stale.example.invalid".to_string(),
                query_type: 1,
                resolved_ips: vec![dst_ip],
                timestamp_ms: now_ms - 90_000,
            })
            .await
            .expect("send stale DnsQuery");
        assert!(wait_until(1_000, || engine.metrics().high_priority_processed >= 3).await);
        let permits_before_drop = defense
            .added_wfp()
            .iter()
            .filter(|f| f.allow && f.remote_ip == Some(dst_ip))
            .count();

        assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
            os_filter_id: 3,
            rule_handle: 3,
            exe_path: tool_exe.to_string(),
            protocol: 6,
            dst_ip,
            dst_port: 443,
            timestamp_ms: now_ms,
        }));

        assert!(
            wait_until(1_500, || {
                store
                    .list_alerts(Some(AlertStatus::Pending), 10)
                    .map(|a| !a.is_empty())
                    .unwrap_or(false)
            })
            .await,
            "stale >60s DNS under multi-candidate ambiguity must fall back to app_level_ambiguous alert"
        );
        let permits_after_drop = defense
            .added_wfp()
            .iter()
            .filter(|f| f.allow && f.remote_ip == Some(dst_ip))
            .count();
        assert_eq!(
            permits_after_drop, permits_before_drop,
            "stale >60s DNS must not authorize any new WFP Permit on WfpDropEvent"
        );
        assert!(defense.suspends().is_empty());

        engine.shutdown_and_flush().await.expect("shutdown Part C");
    }
}

struct ShutdownTestBinaryInspector {
    target_substr: String,
    entered: Arc<AtomicBool>,
    delay_ms: u64,
    cancelled_observed: Arc<AtomicBool>,
}

impl BinaryInspector for ShutdownTestBinaryInspector {
    fn inspect(&self, exe_path: &str) -> BinaryIdentity {
        BinaryIdentity {
            exe_path: exe_path.to_string(),
            sha256: Some("f".repeat(64)),
            authenticode: None,
        }
    }

    fn inspect_cancellable(
        &self,
        exe_path: &str,
        cancel: &AtomicBool,
        fast_skip_on_shutdown: bool,
    ) -> ledr_daemon::InspectOutcome {
        if exe_path
            .to_ascii_lowercase()
            .contains(&self.target_substr.to_ascii_lowercase())
        {
            self.entered.store(true, Ordering::Release);
            if fast_skip_on_shutdown || cancel.load(Ordering::Acquire) {
                self.cancelled_observed.store(true, Ordering::Release);
                return ledr_daemon::InspectOutcome::Cancelled;
            }
            let wait_fn = || {
                let deadline = Instant::now() + Duration::from_millis(self.delay_ms);
                while Instant::now() < deadline {
                    if cancel.load(Ordering::Acquire) {
                        self.cancelled_observed.store(true, Ordering::Release);
                        return ledr_daemon::InspectOutcome::Cancelled;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                ledr_daemon::InspectOutcome::Completed(self.inspect(exe_path))
            };
            if tokio::runtime::Handle::try_current().is_ok_and(|h| {
                h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread
            }) {
                return tokio::task::block_in_place(wait_fn);
            }
            return wait_fn();
        }
        ledr_daemon::InspectOutcome::Completed(self.inspect(exe_path))
    }
}

/// `DAEMON-P3-54` (`FU-E2E-05`, `E2E-P3-06`):
/// - Part A: Fast CLI shutdown (`shutdown_skip_cold_binary_inspect: true` +
///   `signal_early_shutdown()`) skips cold binary inspection cleanly (`Ok(())`), truncates WAL to
///   0 bytes, detaches a wedged NRD thread, and drops the independent Tokio runtime in `< 300 ms`.
/// - Part B: Genuine drain timeout (`shutdown_flush_timeout_ms: 350`) returns `Err` containing
///   `"timeout"` (`DAEMON-P3-37` compatibility), emits 0 false alerts/suspends from cancelled
///   inspection, truncates WAL to 0 bytes, keeps post-shutdown writes closed (`-wal` remains
///   absent or 0 bytes), and drops the independent Tokio runtime in `< 300 ms`.
#[test]
fn daemon_p3_54_shutdown_wal_zero_bytes_and_nrd_detach() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::windows::named_pipe::ServerOptions;

    struct TempDirGuard(std::path::PathBuf);
    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct PipeServerGuard {
        release_tx: Option<tokio::sync::oneshot::Sender<()>>,
        thread: Option<std::thread::JoinHandle<()>>,
    }
    impl PipeServerGuard {
        fn stop_and_join(&mut self) {
            if let Some(tx) = self.release_tx.take() {
                let _ = tx.send(());
            }
            if let Some(jh) = self.thread.take() {
                let _ = jh.join();
            }
        }
    }
    impl Drop for PipeServerGuard {
        fn drop(&mut self) {
            self.stop_and_join();
        }
    }

    fn spawn_wedged_nrd_pipe() -> (String, PipeServerGuard) {
        let pipe_leaf = format!(
            "localedr-p3-54-nrd-{}-{}",
            std::process::id(),
            PIPE_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let pipe_path = format!(r"\\.\pipe\{pipe_leaf}");
        let feed_url = format!("file://./pipe/{pipe_leaf}");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, mut release_rx) = tokio::sync::oneshot::channel::<()>();
        let pipe_path_bg = pipe_path.clone();

        let thread = std::thread::Builder::new()
            .name("test-p3-54-nrd-pipe".to_string())
            .spawn(move || {
                let pipe_rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build helper pipe runtime");
                pipe_rt.block_on(async move {
                    let mut server = ServerOptions::new()
                        .first_pipe_instance(true)
                        .out_buffer_size(1024)
                        .create(&pipe_path_bg)
                        .expect("create pipe");
                    let _ = ready_tx.send(());
                    let connected = tokio::select! {
                        res = server.connect() => res.is_ok(),
                        _ = &mut release_rx => false,
                        _ = tokio::time::sleep(Duration::from_secs(10)) => false,
                    };
                    if connected {
                        let wrote = tokio::select! {
                            res = async {
                                server.write_all(b"\n").await?;
                                server.flush().await
                            } => res.is_ok(),
                            _ = &mut release_rx => false,
                            _ = tokio::time::sleep(Duration::from_secs(5)) => false,
                        };
                        if wrote {
                            let _ =
                                tokio::time::timeout(Duration::from_secs(10), &mut release_rx)
                                    .await;
                        }
                        let _ = server.disconnect();
                    }
                });
            })
            .expect("spawn pipe server");
        ready_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("pipe ready");
        (
            feed_url,
            PipeServerGuard {
                release_tx: Some(release_tx),
                thread: Some(thread),
            },
        )
    }

    fn assert_wal_zero(db_path: &Path) {
        let wal_path = std::path::PathBuf::from(format!("{}-wal", db_path.display()));
        if wal_path.exists() {
            let len = std::fs::metadata(&wal_path).expect("stat wal").len();
            assert_eq!(len, 0, "expected 0-byte WAL at {}", wal_path.display());
        }
    }

    let tmp_dir = std::env::temp_dir().join(format!(
        "ledr-p3-54-wal-{}-{}",
        std::process::id(),
        PIPE_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&tmp_dir).expect("create temp dir for DAEMON-P3-54");
    let _tmp_guard = TempDirGuard(tmp_dir.clone());

    // Part A: Fast CLI shutdown path -> Ok(()), -wal == 0, NRD detached, Runtime::drop < 300ms.
    {
        let db_path = tmp_dir.join("shutdown_fast_wal.db");
        let (feed_url, mut pipe_guard) = spawn_wedged_nrd_pipe();
        let subject_rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("build runtime A");

        let now_ms = current_unix_ms();
        let marker_proc = ProcessIdentity::new(9921, unix_ms_to_filetime(now_ms - 1_000));
        let marker_id = marker_proc.instance_id();
        let cold_proc = ProcessIdentity::new(9922, unix_ms_to_filetime(now_ms - 500));
        let cancelled_observed = Arc::new(AtomicBool::new(false));
        let cancelled_clone = Arc::clone(&cancelled_observed);

        let db_rt = db_path.clone();
        let marker_id_rt = marker_id.clone();
        subject_rt.block_on(async move {
            let store = LedrStore::open(&db_rt).expect("open store");
            let defense = Arc::new(MockWfpDefense::new());
            let notifier = Arc::new(MockNotifier::default());
            let entered = Arc::new(AtomicBool::new(false));
            let inspector = Arc::new(ShutdownTestBinaryInspector {
                target_substr: "cold_electron.exe".to_string(),
                entered: Arc::clone(&entered),
                delay_ms: 2_500,
                cancelled_observed: cancelled_clone,
            });

            let engine = start_test_engine(
                store.clone(),
                DaemonConfig {
                    pipe_name: unique_test_pipe_name(),
                    nrd_refresh_enabled: true,
                    nrd_refresh_interval_ms: 200,
                    nrd_feed_urls: vec![feed_url],
                    shutdown_flush_timeout_ms: 800,
                    batch_flush_interval_ms: 500,
                    shutdown_skip_cold_binary_inspect: true,
                    ..DaemonConfig::default()
                },
                defense.clone(),
                notifier,
                inspector,
            );

            let nrd_token = engine.nrd_cancel_token();
            assert!(
                wait_until(3_000, || {
                    nrd_token.blocking_read_entries() >= 2
                        && nrd_token.is_blocking_read_active()
                        && engine.is_nrd_refresh_in_flight()
                })
                .await
            );

            send_process_start(&engine.sender(), marker_proc, r"C:\Tools\fast_marker.exe").await;
            send_process_start(&engine.sender(), cold_proc, r"C:\Apps\cold_electron.exe").await;
            assert!(wait_until(1_000, || engine.metrics().high_priority_processed >= 2).await);

            // Trigger early shutdown (like Ctrl+C in main.rs), then send cold NetworkConnect.
            engine.signal_early_shutdown();
            engine
                .sender()
                .send(SensorEvent::NetworkConnect {
                    pid: cold_proc.pid,
                    protocol: 6,
                    dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 120)),
                    dst_port: 443,
                    domain_hint: None,
                    timestamp_ms: now_ms,
                })
                .await
                .expect("send cold NetworkConnect");

            engine
                .shutdown_and_flush()
                .await
                .expect("fast CLI shutdown with skip_cold_binary_inspect must return Ok(())");

            assert!(
                defense.suspends().is_empty(),
                "skipped cold binary inspection must not trigger suspension"
            );
            let persisted = store
                .list_running_process_instance_ids()
                .expect("running ids");
            assert!(persisted.contains(&marker_id_rt));
            assert_wal_zero(&db_rt);
        });

        assert!(
            cancelled_observed.load(Ordering::Acquire),
            "shutdown_skip_cold_binary_inspect must fast-skip cold binary inspection"
        );
        let drop_started = Instant::now();
        drop(subject_rt);
        assert!(
            drop_started.elapsed() < Duration::from_millis(300),
            "Runtime::drop A must not hang on wedged NRD thread (took {:?})",
            drop_started.elapsed()
        );
        pipe_guard.stop_and_join();
    }

    // Part B: Genuine drain timeout -> Err("timeout"), 0 false alerts/suspends, closed write gate.
    {
        let db_path = tmp_dir.join("shutdown_timeout_wal.db");
        let (feed_url, mut pipe_guard) = spawn_wedged_nrd_pipe();
        let subject_rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("build runtime B");

        let now_ms = current_unix_ms();
        let slow_proc = ProcessIdentity::new(9931, unix_ms_to_filetime(now_ms - 500));
        let entered = Arc::new(AtomicBool::new(false));
        let cancelled_observed = Arc::new(AtomicBool::new(false));
        let entered_clone = Arc::clone(&entered);
        let cancelled_clone = Arc::clone(&cancelled_observed);

        let db_rt = db_path.clone();
        subject_rt.block_on(async move {
            let store = LedrStore::open(&db_rt).expect("open store");
            let defense = Arc::new(MockWfpDefense::new());
            let notifier = Arc::new(MockNotifier::default());
            let inspector = Arc::new(ShutdownTestBinaryInspector {
                target_substr: "slow_timeout.exe".to_string(),
                entered: entered_clone,
                delay_ms: 5_000,
                cancelled_observed: cancelled_clone,
            });

            let engine = start_test_engine(
                store.clone(),
                DaemonConfig {
                    pipe_name: unique_test_pipe_name(),
                    nrd_refresh_enabled: true,
                    nrd_refresh_interval_ms: 200,
                    nrd_feed_urls: vec![feed_url],
                    shutdown_flush_timeout_ms: 350,
                    batch_flush_interval_ms: 500,
                    shutdown_skip_cold_binary_inspect: false,
                    ..DaemonConfig::default()
                },
                defense.clone(),
                notifier,
                inspector,
            );

            let nrd_token = engine.nrd_cancel_token();
            assert!(
                wait_until(3_000, || {
                    nrd_token.blocking_read_entries() >= 2
                        && nrd_token.is_blocking_read_active()
                        && engine.is_nrd_refresh_in_flight()
                })
                .await
            );

            send_process_start(&engine.sender(), slow_proc, r"C:\Tools\slow_timeout.exe").await;
            assert!(wait_until(1_000, || engine.metrics().high_priority_processed >= 1).await);

            engine
                .sender()
                .send(SensorEvent::NetworkConnect {
                    pid: slow_proc.pid,
                    protocol: 6,
                    dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 121)),
                    dst_port: 443,
                    domain_hint: None,
                    timestamp_ms: now_ms,
                })
                .await
                .expect("send slow NetworkConnect");
            assert!(
                wait_until(1_000, || entered.load(Ordering::Acquire)).await,
                "worker must enter slow_timeout inspect"
            );

            let err = engine
                .shutdown_and_flush()
                .await
                .expect_err("genuine drain overrun must return timeout Err (DAEMON-P3-37)");
            assert!(
                err.to_string().to_ascii_lowercase().contains("timeout"),
                "error must contain 'timeout': {err}"
            );

            assert!(
                defense.suspends().is_empty(),
                "cancelled inspection must never produce a suspension"
            );
            assert!(
                store.list_alerts(None, 20).expect("alerts").is_empty(),
                "cancelled inspection must produce 0 false alerts"
            );
            assert_wal_zero(&db_rt);

            // Post-shutdown write attempts via IPC/engine helpers fail closed and leave WAL 0.
            let ev_res = engine.record_browser_event(
                ledr_proto::BrowserSecurityEventType::ClickFixPastejacking,
                "https://post-shutdown.example.invalid",
                Some("blocked"),
                now_ms + 100,
            );
            assert!(matches!(ev_res, Err(ledr_daemon::BrowserReportError::Cancelled)));

            let dl_res = engine.record_browser_download_origin(
                r"C:\Users\alice\Downloads\post_shutdown.bin",
                "https://post-shutdown.example.invalid",
                None,
                None,
                now_ms + 100,
            );
            assert!(matches!(dl_res, Err(ledr_daemon::BrowserReportError::Cancelled)));
            assert_wal_zero(&db_rt);
        });

        let drop_started = Instant::now();
        drop(subject_rt);
        assert!(
            drop_started.elapsed() < Duration::from_millis(300),
            "Runtime::drop B must not hang on wedged NRD thread (took {:?})",
            drop_started.elapsed()
        );
        pipe_guard.stop_and_join();
    }
}

/// `DAEMON-P3-55` (`FU-E2E-05`):
/// Confirms `store_write_gate` is strictly scoped to a shut-down `DaemonEngine` instance, does
/// not permanently poison the shared [`LedrStore`], and `start_with_motw_inspector` clears the
/// store's cooperative shutdown flag so a second `DaemonEngine` cleanly reuses the store.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_p3_55_store_write_gate_engine_scoped_and_store_reusable() {
    struct TempDirGuard(std::path::PathBuf);
    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    let tmp_dir = std::env::temp_dir().join(format!(
        "ledr-p3-55-reuse-{}-{}",
        std::process::id(),
        PIPE_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&tmp_dir).expect("create temp dir for DAEMON-P3-55");
    let _tmp_guard = TempDirGuard(tmp_dir.clone());
    let db_path = tmp_dir.join("store_reuse_wal.db");
    let wal_path = std::path::PathBuf::from(format!("{}-wal", db_path.display()));

    let store = LedrStore::open(&db_path).expect("open file-backed store");
    let now_ms = current_unix_ms();

    let engine1 = start_test_engine(
        store.clone(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            shutdown_flush_timeout_ms: 800,
            ..DaemonConfig::default()
        },
        Arc::new(MockWfpDefense::new()),
        Arc::new(MockNotifier::default()),
        Arc::new(MapBinaryInspector::default()),
    );
    let p1 = ProcessIdentity::new(9941, unix_ms_to_filetime(now_ms - 500));
    send_process_start(&engine1.sender(), p1, r"C:\Tools\reuse1.exe").await;
    assert!(wait_until(1_000, || engine1.metrics().high_priority_processed >= 1).await);

    engine1
        .shutdown_and_flush()
        .await
        .expect("engine1 shutdown must succeed");
    if wal_path.exists() {
        assert_eq!(std::fs::metadata(&wal_path).expect("stat wal 1").len(), 0);
    }

    // Closed engine1 rejects new engine-mediated writes and does not regenerate `-wal`.
    let closed_err = engine1.record_browser_event(
        ledr_proto::BrowserSecurityEventType::ClickFixPastejacking,
        "https://closed-engine1.example.invalid",
        None,
        now_ms + 10,
    );
    assert!(matches!(closed_err, Err(ledr_daemon::BrowserReportError::Cancelled)));
    if wal_path.exists() {
        assert_eq!(std::fs::metadata(&wal_path).expect("stat wal post close").len(), 0);
    }

    // Direct store writes remain operational for callers reusing the same LedrStore (`e2e_blockers`).
    store
        .record_alert(&AlertRecord {
            alert_id: "alert-p3-55-direct-reuse".to_string(),
            timestamp_ms: now_ms + 20,
            severity: AlertSeverity::Low,
            source_layer: "LAYER_4_BROWSER".to_string(),
            rule_id: "LEDR-TEST-REUSE".to_string(),
            title: "Direct store reuse check".to_string(),
            process_instance_id: None,
            process_suspended: false,
            status: AlertStatus::Pending,
            context_json: "{}".to_string(),
            resolved_at_ms: None,
        })
        .expect("direct store.record_alert on reused LedrStore must succeed");

    let engine2 = start_test_engine(
        store.clone(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            shutdown_flush_timeout_ms: 800,
            ..DaemonConfig::default()
        },
        Arc::new(MockWfpDefense::new()),
        Arc::new(MockNotifier::default()),
        Arc::new(MapBinaryInspector::default()),
    );
    assert!(
        !store.is_shutdown_requested(),
        "starting engine2 on reused store must reset shutdown_requested flag"
    );

    let p2 = ProcessIdentity::new(9942, unix_ms_to_filetime(now_ms + 50));
    send_process_start(&engine2.sender(), p2, r"C:\Tools\reuse2.exe").await;
    assert!(wait_until(1_000, || engine2.metrics().high_priority_processed >= 1).await);

    engine2
        .shutdown_and_flush()
        .await
        .expect("engine2 shutdown must succeed");
    if wal_path.exists() {
        assert_eq!(std::fs::metadata(&wal_path).expect("stat wal 2").len(), 0);
    }
    let reopened_alerts = store.list_alerts(Some(AlertStatus::Pending), 10).expect("alerts");
    assert!(reopened_alerts.iter().any(|a| a.alert_id == "alert-p3-55-direct-reuse"));
}

