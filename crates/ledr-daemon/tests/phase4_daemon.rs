//! Phase 4A integration tests for `ledr-daemon` (`DAEMON-P4-01`..`DAEMON-P4-24`):
//! `ReportDownloadOrigin`, 3-stage MOTW attribution, `L-18` pre-emptive WFP restrictions,
//! `ReportBrowserEvent` severity/dedup/`L-19` notification suppression, `LAYER_4_BROWSER`
//! alert resolution, bridge IPC auth, `spawn_blocking` responsiveness, burst budget,
//! delayed MOTW observe-to-enforce escalation, startup seed MOTW backlog deduplication,
//! Stage 2 `(sha256, generation)` cache invalidation, default cancellable SHA-256 contract,
//! case-preserving seed MOTW grouping, non-blocking late attribution with fair drain,
//! bounded late-slot reservation under saturated real-time process MOTW bursts, and
//! non-overwriting SQLite MOTW history backfill for short-lived exited processes without
//! granting late L-18 WFP blocks.

use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ledr_daemon::{
    start_ipc_server, verify_caller_identity, ActiveProcessEntry, BinaryInspector,
    BrowserEventOutcome, BrowserReportError, DaemonConfig, DaemonEngine, LiveProcessInspector,
    MotwInspector, MotwMatchStage, NotificationDispatcher, OutboundEnforcementMode,
    WindowsBinaryInspector, WindowsMotwInspector, MAX_BROWSER_EVENT_DETAILS_BYTES,
};
use ledr_proto::{
    read_ipc_frame, write_ipc_frame, ActiveDefenseController, AlertDecision, AlertRecord,
    AlertSeverity, AlertStatus, AllowlistRuleRecord, AuthenticodeInfo, BrowserSecurityEventType,
    CanaryCategory, FrameError, IpcRequest, IpcResponse, ProcessIdentity, RuleScope,
    ScopedPolicyRuleRecord, SensorEvent, ACTIVE_PROCESS_TABLE_CAPACITY, AUTHORIZED_BRIDGE_EXE_PATH,
    HIGH_PRIORITY_CHANNEL_CAPACITY, TELEMETRY_CHANNEL_CAPACITY,
};
use ledr_rules::{
    compute_file_sha256_hex, BinaryIdentity, EarlyPruner, FieldCondition, MatchModifier,
    SigmaEngine, SigmaField, SigmaRule,
};
use ledr_sensor_win::etw::{CapturedProcessSnapshot, LiveProcessInfo, ProcessPackageInfo};
use ledr_sensor_win::{write_zone_identifier, MotwZoneInfo, WfpDropEvent};
use ledr_store::{LedrStore, ProcessPackageRecord};

static PIPE_SEQ: AtomicU64 = AtomicU64::new(1);
static TEMP_SEQ: AtomicU64 = AtomicU64::new(1);

fn unique_test_pipe_name() -> String {
    let seq = PIPE_SEQ.fetch_add(1, Ordering::Relaxed);
    format!(r"\\.\pipe\localedr-p4-test-{}-{seq}", std::process::id())
}

fn unix_ms_to_filetime(unix_ms: i64) -> u64 {
    const EPOCH_DIFF_100NS: u64 = 116_444_736_000_000_000;
    EPOCH_DIFF_100NS.saturating_add(unix_ms.max(0) as u64 * 10_000)
}

struct TestTempDir(PathBuf);

impl TestTempDir {
    fn new(prefix: &str) -> Self {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "ledr-p4-daemon-{prefix}-{}-{seq}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }
}

impl Drop for TestTempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn send_pipe_request(pipe_name: &str, req: &IpcRequest) -> IpcResponse {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(pipe_name)
        {
            Ok(mut pipe) => {
                write_ipc_frame(&mut pipe, req).expect("write IPC request");
                return read_ipc_frame::<_, IpcResponse>(&mut pipe).expect("read IPC response");
            }
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

async fn wait_high_priority_processed(engine: &DaemonEngine, expected: u64, context: &str) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while engine.metrics().high_priority_processed < expected {
        assert!(Instant::now() < deadline, "timed out waiting for {context}");
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WfpCall {
    handle: u64,
    exe_path: String,
    remote_ip: Option<IpAddr>,
    allow: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScopedWfpCall {
    handle: u64,
    exe_path: String,
    package_sid: Option<String>,
    remote_ip: Option<IpAddr>,
    allow: bool,
}

#[derive(Default)]
struct MockDefense {
    next_handle: AtomicU64,
    suspends: Mutex<Vec<ProcessIdentity>>,
    resumes: Mutex<Vec<ProcessIdentity>>,
    terminates: Mutex<Vec<ProcessIdentity>>,
    added_wfp: Mutex<Vec<WfpCall>>,
    added_scoped_wfp: Mutex<Vec<ScopedWfpCall>>,
    removed_wfp: Mutex<Vec<u64>>,
    fail_next_scoped_add: AtomicBool,
    fail_next_remove: AtomicBool,
}

impl MockDefense {
    fn new() -> Self {
        Self {
            next_handle: AtomicU64::new(100),
            ..Self::default()
        }
    }

    fn suspends(&self) -> Vec<ProcessIdentity> {
        self.suspends.lock().expect("lock suspends").clone()
    }

    fn terminates(&self) -> Vec<ProcessIdentity> {
        self.terminates.lock().expect("lock terminates").clone()
    }

    fn added_wfp(&self) -> Vec<WfpCall> {
        self.added_wfp.lock().expect("lock added_wfp").clone()
    }

    fn added_scoped_wfp(&self) -> Vec<ScopedWfpCall> {
        self.added_scoped_wfp
            .lock()
            .expect("lock added_scoped_wfp")
            .clone()
    }

    fn removed_wfp(&self) -> Vec<u64> {
        self.removed_wfp.lock().expect("lock removed_wfp").clone()
    }

    fn set_fail_next_scoped_add(&self, fail: bool) {
        self.fail_next_scoped_add.store(fail, Ordering::Release);
    }

    fn set_fail_next_remove(&self, fail: bool) {
        self.fail_next_remove.store(fail, Ordering::Release);
    }
}

impl ActiveDefenseController for MockDefense {
    fn suspend_process(&self, target: &ProcessIdentity, _include_children: bool) -> Result<(), String> {
        self.suspends.lock().expect("lock suspends").push(*target);
        Ok(())
    }

    fn resume_process(&self, target: &ProcessIdentity) -> Result<(), String> {
        self.resumes.lock().expect("lock resumes").push(*target);
        Ok(())
    }

    fn terminate_process(
        &self,
        target: &ProcessIdentity,
        _include_children: bool,
    ) -> Result<(), String> {
        self.terminates.lock().expect("lock terminates").push(*target);
        Ok(())
    }

    fn add_wfp_app_rule(
        &self,
        exe_path: &Path,
        remote_ip: Option<IpAddr>,
        allow: bool,
    ) -> Result<u64, String> {
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.added_wfp.lock().expect("lock added_wfp").push(WfpCall {
            handle,
            exe_path: exe_path.display().to_string(),
            remote_ip,
            allow,
        });
        Ok(handle)
    }

    fn add_wfp_scoped_app_rule(
        &self,
        exe_path: &Path,
        package_sid: Option<&str>,
        remote_ip: Option<IpAddr>,
        allow: bool,
    ) -> Result<u64, String> {
        let Some(pkg_sid) = package_sid.map(str::trim).filter(|s| !s.is_empty()) else {
            return self.add_wfp_app_rule(exe_path, remote_ip, allow);
        };
        if self.fail_next_scoped_add.swap(false, Ordering::AcqRel) {
            return Err(format!(
                "injected scoped WFP add failure for {} ({pkg_sid})",
                exe_path.display()
            ));
        }
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.added_scoped_wfp
            .lock()
            .expect("lock added_scoped_wfp")
            .push(ScopedWfpCall {
                handle,
                exe_path: exe_path.display().to_string(),
                package_sid: Some(pkg_sid.to_string()),
                remote_ip,
                allow,
            });
        Ok(handle)
    }

    fn remove_wfp_rule(&self, filter_id: u64) -> Result<(), String> {
        if self.fail_next_remove.swap(false, Ordering::AcqRel) {
            return Err(format!("injected WFP remove failure for {filter_id}"));
        }
        self.removed_wfp.lock().expect("lock removed_wfp").push(filter_id);
        Ok(())
    }
}

#[derive(Default)]
struct RecordingNotifier {
    alerts: Mutex<Vec<AlertRecord>>,
}

impl RecordingNotifier {
    fn alerts(&self) -> Vec<AlertRecord> {
        self.alerts.lock().expect("lock alerts").clone()
    }
}

impl NotificationDispatcher for RecordingNotifier {
    fn notify_alert(&self, alert: &AlertRecord) -> Result<(), String> {
        self.alerts.lock().expect("lock alerts").push(alert.clone());
        Ok(())
    }
}

#[derive(Default)]
struct MapBinaryInspector {
    entries: Mutex<HashMap<String, BinaryIdentity>>,
    calls: Mutex<Vec<String>>,
}

impl MapBinaryInspector {
    fn insert(&self, path: &str, identity: BinaryIdentity) {
        self.entries
            .lock()
            .expect("lock entries")
            .insert(path.replace('/', "\\").to_ascii_lowercase(), identity);
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("lock calls").clone()
    }
}

impl BinaryInspector for MapBinaryInspector {
    fn inspect(&self, exe_path: &str) -> BinaryIdentity {
        self.calls
            .lock()
            .expect("lock calls")
            .push(exe_path.to_string());
        let key = exe_path.replace('/', "\\").to_ascii_lowercase();
        self.entries
            .lock()
            .expect("lock entries")
            .get(&key)
            .cloned()
            .unwrap_or_else(|| BinaryIdentity {
                exe_path: exe_path.to_string(),
                sha256: None,
                authenticode: None,
            })
    }
}

#[derive(Default)]
struct NullLiveProcessInspector;

impl LiveProcessInspector for NullLiveProcessInspector {
    fn inspect_live_process(&self, _pid: u32) -> Option<LiveProcessInfo> {
        None
    }
}

#[derive(Default)]
struct MapMotwInspector {
    zones: Mutex<HashMap<String, MotwZoneInfo>>,
    calls: Mutex<Vec<String>>,
}

impl MapMotwInspector {
    fn insert(&self, path: &str, zone: MotwZoneInfo) {
        self.zones
            .lock()
            .expect("lock zones")
            .insert(path.replace('/', "\\").to_ascii_lowercase(), zone);
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("lock calls").clone()
    }
}

impl MotwInspector for MapMotwInspector {
    fn read_zone_identifier(&self, path: &Path) -> Option<MotwZoneInfo> {
        let raw = path.display().to_string();
        self.calls.lock().expect("lock calls").push(raw.clone());
        let key = raw.replace('/', "\\").to_ascii_lowercase();
        self.zones.lock().expect("lock zones").get(&key).cloned()
    }
}

struct BlockingGateMotwInspector {
    entered: Arc<(Mutex<usize>, Condvar)>,
    released: Arc<(Mutex<bool>, Condvar)>,
    completed: Arc<(Mutex<usize>, Condvar)>,
    target_substring: Option<String>,
    return_zone: Option<MotwZoneInfo>,
}

impl BlockingGateMotwInspector {
    fn new(
        entered: Arc<(Mutex<usize>, Condvar)>,
        released: Arc<(Mutex<bool>, Condvar)>,
        completed: Arc<(Mutex<usize>, Condvar)>,
    ) -> Self {
        Self {
            entered,
            released,
            completed,
            target_substring: None,
            return_zone: None,
        }
    }
}

impl MotwInspector for BlockingGateMotwInspector {
    fn read_zone_identifier(&self, path: &Path) -> Option<MotwZoneInfo> {
        if let Some(sub) = self.target_substring.as_deref() {
            let raw = path.display().to_string();
            if !raw.to_ascii_lowercase().contains(&sub.to_ascii_lowercase()) {
                return None;
            }
        }
        {
            let (lock, cvar) = &*self.entered;
            let mut count = lock.lock().expect("lock entered");
            *count += 1;
            cvar.notify_all();
        }
        {
            let (lock, cvar) = &*self.released;
            let mut flag = lock.lock().expect("lock released");
            while !*flag {
                flag = cvar.wait(flag).expect("wait released");
            }
        }
        {
            let (lock, cvar) = &*self.completed;
            let mut count = lock.lock().expect("lock completed");
            *count += 1;
            cvar.notify_all();
        }
        self.return_zone.clone()
    }
}

struct GateReleaseGuard(Arc<(Mutex<bool>, Condvar)>);

impl Drop for GateReleaseGuard {
    fn drop(&mut self) {
        let (lock, cvar) = &*self.0;
        let mut flag = lock.lock().unwrap_or_else(|e| e.into_inner());
        *flag = true;
        cvar.notify_all();
    }
}

#[derive(Default)]
struct CountingBinaryInspector {
    inner: WindowsBinaryInspector,
    inspect_calls: AtomicU64,
    sha256_calls: AtomicU64,
}

impl CountingBinaryInspector {
    fn inspect_calls(&self) -> u64 {
        self.inspect_calls.load(Ordering::Acquire)
    }

    fn sha256_calls(&self) -> u64 {
        self.sha256_calls.load(Ordering::Acquire)
    }
}

impl BinaryInspector for CountingBinaryInspector {
    fn inspect(&self, exe_path: &str) -> BinaryIdentity {
        self.inspect_calls.fetch_add(1, Ordering::AcqRel);
        self.inner.inspect(exe_path)
    }

    fn compute_sha256(&self, exe_path: &str) -> Option<String> {
        self.sha256_calls.fetch_add(1, Ordering::AcqRel);
        self.inner.compute_sha256(exe_path)
    }

    fn compute_sha256_cancellable(
        &self,
        exe_path: &str,
        max_bytes: u64,
        cancel: &AtomicBool,
    ) -> std::io::Result<Option<String>> {
        self.inner.compute_sha256_cancellable(exe_path, max_bytes, cancel)
    }
}

fn wait_count_reached(pair: &(Mutex<usize>, Condvar), target: usize) {
    let (lock, cvar) = pair;
    let mut count = lock.lock().expect("lock count");
    while *count < target {
        let (next, timed) = cvar
            .wait_timeout(count, Duration::from_secs(3))
            .expect("wait count");
        count = next;
        assert!(
            !timed.timed_out() || *count >= target,
            "timed out waiting for gate count >= {target} (got {})",
            *count
        );
    }
}

fn try_send_pipe_request(pipe_name: &str, req: &IpcRequest) -> Result<IpcResponse, FrameError> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(pipe_name)
        {
            Ok(mut pipe) => {
                write_ipc_frame(&mut pipe, req)?;
                return read_ipc_frame::<_, IpcResponse>(&mut pipe);
            }
            Err(err)
                if Instant::now() < deadline
                    && matches!(err.raw_os_error(), Some(231) | Some(2)) =>
            {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(err) => return Err(FrameError::Io(err)),
        }
    }
}

#[tokio::test]
async fn daemon_p4_01_report_download_origin_hashes_file_and_enriches_ads() {
    let dir = TestTempDir::new("p4-01");
    let file_path = dir.0.join("installer.exe");
    let payload = b"LocalEDR-Phase4A-Sample-Download-Payload";
    std::fs::write(&file_path, payload).expect("write dummy download");
    let expected_sha = compute_file_sha256_hex(&file_path).expect("hash file");

    let motw = Arc::new(MapMotwInspector::default());
    motw.insert(
        &file_path.display().to_string(),
        MotwZoneInfo {
            zone_id: 3,
            host_url: Some("https://cdn-frame.example.invalid/installer.exe".to_string()),
            referrer_url: Some("https://ads-ref.example.invalid/landing".to_string()),
        },
    );

    let store = LedrStore::open_in_memory().expect("open store");
    let engine = DaemonEngine::start_with_motw_inspector(
        store.clone(),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        Arc::new(MockDefense::new()),
        Arc::new(RecordingNotifier::default()),
        Arc::new(WindowsBinaryInspector::new()),
        Arc::new(NullLiveProcessInspector),
        motw,
    );

    let extended_mixed = format!(r"\\?\{}", file_path.display()).replace('\\', "/");
    let recorded = engine
        .record_browser_download_origin(
            &extended_mixed,
            "https://tab.example.invalid/download",
            None,
            None,
            1_760_001_000_000,
        )
        .expect("record download origin");

    assert_eq!(recorded.file_path, file_path.display().to_string());
    assert_eq!(recorded.sha256.as_deref(), Some(expected_sha.as_str()));
    assert_eq!(
        recorded.frame_url.as_deref(),
        Some("https://cdn-frame.example.invalid/installer.exe")
    );
    assert_eq!(
        recorded.referrer_url.as_deref(),
        Some("https://ads-ref.example.invalid/landing")
    );

    // If HostUrl matches tab_url, frame_url must stay None instead of duplicating tab_url.
    let same_host_rec = engine
        .record_browser_download_origin(
            &file_path.display().to_string(),
            "https://cdn-frame.example.invalid/installer.exe",
            None,
            Some("https://explicit-ref.example.invalid/"),
            1_760_001_000_500,
        )
        .expect("record download origin with matching HostUrl");
    assert_eq!(same_host_rec.frame_url, None);
    assert_eq!(
        same_host_rec.referrer_url.as_deref(),
        Some("https://explicit-ref.example.invalid/")
    );

    let snap = store.query_flight_recorder(10, None).expect("query store");
    assert_eq!(snap.download_origins.len(), 2);
    assert_eq!(snap.download_origins[0].frame_url, None);
    assert_eq!(
        snap.download_origins[1].sha256.as_deref(),
        Some(expected_sha.as_str())
    );

    engine.shutdown_and_flush().await.expect("shutdown");
}

#[tokio::test]
async fn daemon_p4_02_report_download_origin_over_hash_limit_still_records_origin_and_ads() {
    let dir = TestTempDir::new("p4-02");
    let large_path = dir.0.join("oversized.iso");
    std::fs::write(&large_path, vec![b'X'; 64]).expect("write file over custom 16B limit");

    let motw = Arc::new(MapMotwInspector::default());
    motw.insert(
        &large_path.display().to_string(),
        MotwZoneInfo {
            zone_id: 3,
            host_url: Some("https://iso-mirror.example.invalid/oversized.iso".to_string()),
            referrer_url: Some("https://portal.example.invalid/iso".to_string()),
        },
    );

    let store = LedrStore::open_in_memory().expect("open store");
    let engine = DaemonEngine::start_with_motw_inspector(
        store.clone(),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            download_hash_max_bytes: 16,
            ..DaemonConfig::default()
        },
        Arc::new(MockDefense::new()),
        Arc::new(RecordingNotifier::default()),
        Arc::new(WindowsBinaryInspector::new()),
        Arc::new(NullLiveProcessInspector),
        motw,
    );

    assert!(matches!(
        engine.record_browser_download_origin("   ", "https://x.invalid", None, None, 100),
        Err(BrowserReportError::Invalid(_))
    ));
    assert!(matches!(
        engine.record_browser_download_origin(
            &large_path.display().to_string(),
            "   ",
            None,
            None,
            100
        ),
        Err(BrowserReportError::Invalid(_))
    ));

    let rec = engine
        .record_browser_download_origin(
            &large_path.display().to_string(),
            "https://downloads.example.invalid/iso",
            None,
            None,
            1_760_002_000_000,
        )
        .expect("oversized file still records URL and ADS");
    assert_eq!(rec.sha256, None);
    assert_eq!(
        rec.referrer_url.as_deref(),
        Some("https://portal.example.invalid/iso")
    );
    assert_eq!(
        rec.frame_url.as_deref(),
        Some("https://iso-mirror.example.invalid/oversized.iso")
    );

    engine.shutdown_and_flush().await.expect("shutdown");
}

#[tokio::test]
async fn daemon_p4_03_motw_stage1_path_match_and_alert_context_embedding() {
    let sigma = SigmaEngine::from_json_str(
        r#"{
            "rules": [{
                "id": "TEST-MOTW-SIGMA",
                "title": "Downloaded Executable Launch",
                "severity": "High",
                "description": "Matches evil_dl.exe launch",
                "conditions": [
                    { "field": "Image", "modifier": "EndsWith", "values": ["\\evil_dl.exe"] }
                ]
            }]
        }"#,
    )
    .expect("load test sigma rule");
    let motw = Arc::new(MapMotwInspector::default());
    let exe_path = r"C:\Users\alice\Downloads\evil_dl.exe";
    motw.insert(
        exe_path,
        MotwZoneInfo {
            zone_id: 3,
            host_url: Some("https://cdn.example.invalid/evil_dl.exe".to_string()),
            referrer_url: Some("https://ads-ref.example.invalid/".to_string()),
        },
    );

    let store = LedrStore::open_in_memory().expect("open store");
    let engine = DaemonEngine::start_with_motw_inspector(
        store.clone(),
        sigma,
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        Arc::new(MockDefense::new()),
        Arc::new(RecordingNotifier::default()),
        Arc::new(MapBinaryInspector::default()),
        Arc::new(NullLiveProcessInspector),
        motw,
    );

    engine
        .record_browser_download_origin(
            exe_path,
            "https://phish.example.invalid/dl",
            Some("https://iframe.example.invalid/widget"),
            Some("https://referrer.example.invalid/mail"),
            1_760_003_000_000,
        )
        .expect("record download origin");

    let ident = ProcessIdentity::new(5001, unix_ms_to_filetime(1_760_003_010_000));
    let sender = engine.sender();
    sender
        .send(SensorEvent::ProcessStart {
            identity: ident,
            parent_pid: 4,
            exe_path: exe_path.to_string(),
            command_line: "evil_dl.exe powershell -EncodedCommand VwByAGkAdABlAA==".to_string(),
            user_sid: Some("S-1-5-21-1001".to_string()),
        })
        .await
        .expect("send ProcessStart");
    sender
        .send(SensorEvent::CanaryFileAccess {
            pid: ident.pid,
            target_path: r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Cookies"
                .to_string(),
            category: CanaryCategory::CookieDb,
            access_mask: 1,
            is_write_or_delete: false,
            timestamp_ms: 1_760_003_010_100,
        })
        .await
        .expect("send CanaryFileAccess");
    sender
        .send(SensorEvent::NetworkConnect {
            pid: ident.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42)),
            dst_port: 443,
            domain_hint: Some("c2.example.invalid".to_string()),
            timestamp_ms: 1_760_003_010_200,
        })
        .await
        .expect("send NetworkConnect");

    engine.shutdown_and_flush().await.expect("shutdown");

    let snap = store
        .query_flight_recorder(10, Some(&ident.instance_id()))
        .expect("query proc");
    assert_eq!(snap.processes.len(), 1);
    assert_eq!(
        snap.processes[0].origin_url.as_deref(),
        Some("https://phish.example.invalid/dl")
    );

    let alerts = store.list_alerts(None, 20).expect("list alerts");
    let sigma_alert = alerts
        .iter()
        .find(|a| a.source_layer == "LAYER_2_RULES")
        .expect("Sigma alert");
    let canary_alert = alerts
        .iter()
        .find(|a| a.source_layer == "LAYER_1_CANARY")
        .expect("Canary alert");
    let net_alert = alerts
        .iter()
        .find(|a| a.source_layer == "LAYER_3_NETWORK")
        .expect("Outbound alert");

    for alert in [sigma_alert, canary_alert, net_alert] {
        let ctx: serde_json::Value =
            serde_json::from_str(&alert.context_json).expect("valid alert context_json");
        assert_eq!(
            ctx.get("origin_url").and_then(|v| v.as_str()),
            Some("https://phish.example.invalid/dl"),
            "missing origin_url on {} alert",
            alert.source_layer
        );
        assert_eq!(
            ctx.get("motw_source").and_then(|v| v.as_str()),
            Some("download_path"),
            "missing motw_source on {} alert",
            alert.source_layer
        );
        assert_eq!(
            ctx.get("motw_referrer").and_then(|v| v.as_str()),
            Some("https://referrer.example.invalid/mail")
        );
        assert_eq!(
            ctx.get("motw_frame_url").and_then(|v| v.as_str()),
            Some("https://iframe.example.invalid/widget")
        );
        assert_eq!(ctx.get("motw_zone_id").and_then(|v| v.as_u64()), Some(3));
    }
}

#[tokio::test]
async fn daemon_p4_04_motw_stage2_sha256_match_after_move_and_rename() {
    let dir = TestTempDir::new("p4-04");
    let dl_path = dir.0.join("Downloads").join("downloaded.exe");
    let moved_path = dir.0.join("Desktop").join("renamed_portable.exe");
    std::fs::create_dir_all(dl_path.parent().expect("dl parent")).expect("create dl dir");
    std::fs::create_dir_all(moved_path.parent().expect("moved parent")).expect("create desktop dir");
    std::fs::write(&dl_path, b"unique-motw-binary-content-stage2").expect("write original dl");
    let expected_sha = compute_file_sha256_hex(&dl_path).expect("hash original");

    let store = LedrStore::open_in_memory().expect("open store");
    let engine = DaemonEngine::start_with_motw_inspector(
        store.clone(),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        Arc::new(MockDefense::new()),
        Arc::new(RecordingNotifier::default()),
        Arc::new(WindowsBinaryInspector::new()),
        Arc::new(NullLiveProcessInspector),
        Arc::new(MapMotwInspector::default()),
    );

    engine
        .record_browser_download_origin(
            &dl_path.display().to_string(),
            "https://origin.example.invalid/downloaded.exe",
            None,
            Some("https://ref.example.invalid/portal"),
            1_760_004_000_000,
        )
        .expect("record download origin");

    // Simulate moving and renaming the binary out of Downloads without any ADS.
    std::fs::rename(&dl_path, &moved_path).expect("move downloaded binary");

    let ident = ProcessIdentity::new(5002, unix_ms_to_filetime(1_760_004_010_000));
    let sender = engine.sender();
    sender
        .send(SensorEvent::ProcessStart {
            identity: ident,
            parent_pid: 4,
            exe_path: moved_path.display().to_string(),
            command_line: "renamed_portable.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send ProcessStart");
    sender
        .send(SensorEvent::NetworkConnect {
            pid: ident.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 25)),
            dst_port: 8443,
            domain_hint: None,
            timestamp_ms: 1_760_004_010_200,
        })
        .await
        .expect("send NetworkConnect");

    engine.shutdown_and_flush().await.expect("shutdown");

    let snap = store
        .query_flight_recorder(10, Some(&ident.instance_id()))
        .expect("query proc");
    assert_eq!(snap.processes.len(), 1);
    assert_eq!(
        snap.processes[0].origin_url.as_deref(),
        Some("https://origin.example.invalid/downloaded.exe")
    );
    assert_eq!(
        snap.processes[0].sha256.as_deref(),
        Some(expected_sha.as_str())
    );

    let alerts = store.list_alerts(None, 10).expect("list alerts");
    let net_alert = alerts
        .iter()
        .find(|a| a.source_layer == "LAYER_3_NETWORK")
        .expect("network alert");
    let ctx: serde_json::Value = serde_json::from_str(&net_alert.context_json).expect("ctx json");
    assert_eq!(
        ctx.get("motw_source").and_then(|v| v.as_str()),
        Some("download_sha256")
    );
    assert_eq!(
        ctx.get("motw_referrer").and_then(|v| v.as_str()),
        Some("https://ref.example.invalid/portal")
    );
}

#[tokio::test]
async fn daemon_p4_05_motw_stage3_zone_identifier_ads_fallback_and_zone_threshold() {
    let dir = TestTempDir::new("p4-05");
    let real_ads_exe = dir.0.join("curl_dropped.exe");
    std::fs::write(&real_ads_exe, b"non-browser-ads-binary").expect("write target");
    write_zone_identifier(
        &real_ads_exe,
        &MotwZoneInfo {
            zone_id: 3,
            host_url: Some("https://raw.example.invalid/curl_dropped.exe".to_string()),
            referrer_url: Some("https://docs.example.invalid/".to_string()),
        },
    )
    .expect("write real :Zone.Identifier ADS");

    // Part A: real WindowsMotwInspector end-to-end without any download_origins rows.
    let store = LedrStore::open_in_memory().expect("open store");
    let engine_real = DaemonEngine::start_with_motw_inspector(
        store.clone(),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        Arc::new(MockDefense::new()),
        Arc::new(RecordingNotifier::default()),
        Arc::new(MapBinaryInspector::default()),
        Arc::new(NullLiveProcessInspector),
        Arc::new(WindowsMotwInspector::new()),
    );

    let ident = ProcessIdentity::new(5003, unix_ms_to_filetime(1_760_005_010_000));
    engine_real
        .sender()
        .send(SensorEvent::ProcessStart {
            identity: ident,
            parent_pid: 4,
            exe_path: real_ads_exe.display().to_string(),
            command_line: "curl_dropped.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send ProcessStart");
    engine_real.shutdown_and_flush().await.expect("shutdown");

    let snap = store
        .query_flight_recorder(10, Some(&ident.instance_id()))
        .expect("query proc");
    assert_eq!(
        snap.processes[0].origin_url.as_deref(),
        Some("https://raw.example.invalid/curl_dropped.exe")
    );

    // Part B: ZoneId threshold & preferred_origin_url fallback via MapMotwInspector.
    let mock_motw = Arc::new(MapMotwInspector::default());
    mock_motw.insert(
        r"C:\Temp\intranet_z2.exe",
        MotwZoneInfo {
            zone_id: 2,
            host_url: Some("https://intranet.local/tool.exe".to_string()),
            referrer_url: None,
        },
    );
    mock_motw.insert(
        r"C:\Temp\about_internet_with_ref.exe",
        MotwZoneInfo {
            zone_id: 3,
            host_url: None, // parse_zone_identifier filters out `about:internet`
            referrer_url: Some("https://webmail.example.invalid/".to_string()),
        },
    );
    mock_motw.insert(
        r"C:\Temp\zone3_no_urls.exe",
        MotwZoneInfo {
            zone_id: 3,
            host_url: None,
            referrer_url: None,
        },
    );

    let engine_mock = DaemonEngine::start_with_motw_inspector(
        LedrStore::open_in_memory().expect("open store"),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        Arc::new(MockDefense::new()),
        Arc::new(RecordingNotifier::default()),
        Arc::new(MapBinaryInspector::default()),
        Arc::new(NullLiveProcessInspector),
        mock_motw,
    );

    assert_eq!(
        engine_mock.resolve_process_motw(r"C:\Temp\intranet_z2.exe", None, false),
        None
    );
    let ref_attr = engine_mock
        .resolve_process_motw(r"C:\Temp\about_internet_with_ref.exe", None, false)
        .expect("zone 3 referrer fallback");
    assert_eq!(ref_attr.stage, MotwMatchStage::ZoneIdentifierAds);
    assert_eq!(ref_attr.origin_url, "https://webmail.example.invalid/");
    assert_eq!(ref_attr.zone_id, Some(3));

    let zone_fallback = engine_mock
        .resolve_process_motw(r"C:\Temp\zone3_no_urls.exe", None, false)
        .expect("zone 3 synthetic origin");
    assert_eq!(zone_fallback.origin_url, "motw:zone3");
    assert_eq!(zone_fallback.zone_id, Some(3));

    engine_mock.shutdown_and_flush().await.expect("shutdown");
}

#[tokio::test]
async fn daemon_p4_06_motw_priority_order_and_protected_os_exclusion() {
    let dir = TestTempDir::new("p4-06");
    let tool_path = dir.0.join("multi_stage_tool.exe");
    std::fs::write(&tool_path, b"stage-priority-payload").expect("write dummy tool");
    let tool_str = tool_path.display().to_string();
    let tool_sha = compute_file_sha256_hex(&tool_path).expect("hash");

    let bin_insp = Arc::new(MapBinaryInspector::default());
    bin_insp.insert(
        &tool_str,
        BinaryIdentity {
            exe_path: tool_str.clone(),
            sha256: Some(tool_sha.to_ascii_uppercase()),
            authenticode: None,
        },
    );
    let motw_insp = Arc::new(MapMotwInspector::default());
    motw_insp.insert(
        &tool_str,
        MotwZoneInfo {
            zone_id: 3,
            host_url: Some("https://stage3-ads.example.invalid/tool.exe".to_string()),
            referrer_url: None,
        },
    );
    // Even if ProtectedOs somehow had ADS/download row, ProtectedOs must short-circuit before I/O.
    let svchost = r"C:\Windows\System32\svchost.exe";
    motw_insp.insert(
        svchost,
        MotwZoneInfo {
            zone_id: 3,
            host_url: Some("https://should-never-be-read.invalid/svchost.exe".to_string()),
            referrer_url: None,
        },
    );

    let store = LedrStore::open_in_memory().expect("open store");
    let engine = DaemonEngine::start_with_motw_inspector(
        store,
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        Arc::new(MockDefense::new()),
        Arc::new(RecordingNotifier::default()),
        bin_insp.clone(),
        Arc::new(NullLiveProcessInspector),
        motw_insp.clone(),
    );

    // Record Stage 2 (different path, matching SHA-256) and Stage 1 (matching path).
    engine
        .record_browser_download_origin(
            &dir.0.join("other_name.exe").display().to_string(),
            "https://stage2-sha.example.invalid/other.exe",
            None,
            None,
            1_760_006_000_100,
        )
        .expect("record non-matching path");
    // Seed exact Stage 2 sha record via store directly with tool_sha:
    engine
        .store()
        .record_download_origin(&ledr_proto::DownloadOriginRecord {
            id: None,
            file_path: r"C:\Elsewhere\other_copy.exe".to_string(),
            sha256: Some(tool_sha.clone()),
            tab_url: "https://stage2-sha.example.invalid/copy.exe".to_string(),
            frame_url: None,
            referrer_url: None,
            downloaded_at_ms: 1_760_006_000_200,
        })
        .expect("record sha256 row");

    // Before Stage 1 row exists for `tool_str`, Stage 2 beats Stage 3 ADS.
    let stage2 = engine
        .resolve_process_motw(&tool_str, None, false)
        .expect("stage 2 match");
    assert_eq!(stage2.stage, MotwMatchStage::DownloadSha256);
    assert_eq!(stage2.origin_url, "https://stage2-sha.example.invalid/copy.exe");

    // Once Stage 1 row exists for `tool_str`, Stage 1 beats Stage 2 and Stage 3.
    engine
        .record_browser_download_origin(
            &tool_str,
            "https://stage1-path.example.invalid/tool.exe",
            None,
            None,
            1_760_006_000_300,
        )
        .expect("record stage 1 row");
    let stage1 = engine
        .resolve_process_motw(&tool_str, None, false)
        .expect("stage 1 match");
    assert_eq!(stage1.stage, MotwMatchStage::DownloadPath);
    assert_eq!(stage1.origin_url, "https://stage1-path.example.invalid/tool.exe");

    // ProtectedOs, exited snapshot, and skip_store_ingest must return None without inspecting.
    let calls_before_os = bin_insp.calls().len() + motw_insp.calls().len();
    assert_eq!(engine.resolve_process_motw(svchost, None, false), None);
    assert_eq!(engine.resolve_process_motw(&tool_str, Some(100), false), None);
    assert_eq!(engine.resolve_process_motw(&tool_str, None, true), None);
    let calls_after_os = bin_insp.calls().len() + motw_insp.calls().len();
    assert_eq!(calls_before_os, calls_after_os);

    engine.shutdown_and_flush().await.expect("shutdown");
}

#[tokio::test]
async fn daemon_p4_07_l18_motw_moved_binary_preemptive_wfp_block_and_cleanup() {
    let exe_unbound = r"C:\Tools\portable\moved_unbound.exe";
    let exe_contained = r"C:\Tools\portable\moved_payload.exe";
    let motw_insp = Arc::new(MapMotwInspector::default());
    motw_insp.insert(
        exe_unbound,
        MotwZoneInfo {
            zone_id: 3,
            host_url: Some("https://dropper.example.invalid/moved_unbound.exe".to_string()),
            referrer_url: None,
        },
    );
    motw_insp.insert(
        exe_contained,
        MotwZoneInfo {
            zone_id: 3,
            host_url: Some("https://dropper.example.invalid/moved_payload.exe".to_string()),
            referrer_url: Some("https://forum.example.invalid/thread".to_string()),
        },
    );

    let defense = Arc::new(MockDefense::new());
    let store = LedrStore::open_in_memory().expect("open store");
    // Use PreemptiveOnly mode to verify L-18 promotes moved MOTW binary to Preemptive equivalent!
    let engine = DaemonEngine::start_with_motw_inspector(
        store.clone(),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::PreemptiveOnly,
            ..DaemonConfig::default()
        },
        defense.clone(),
        Arc::new(RecordingNotifier::default()),
        Arc::new(MapBinaryInspector::default()),
        Arc::new(NullLiveProcessInspector),
        motw_insp,
    );

    let sender = engine.classified_sender();

    // Part A: Unbound pre-emptive WFP block installed on ProcessStart is removed on ProcessStop.
    let ident_a = ProcessIdentity::new(5006, unix_ms_to_filetime(1_760_007_000_000));
    sender
        .send(SensorEvent::ProcessStart {
            identity: ident_a,
            parent_pid: 4,
            exe_path: exe_unbound.to_string(),
            command_line: "moved_unbound.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send ProcessStart A");
    wait_high_priority_processed(&engine, 1, "ProcessStart A pre-emptive WFP block").await;
    let added_a = defense.added_wfp();
    assert_eq!(added_a.len(), 1);
    assert_eq!(added_a[0].exe_path, exe_unbound);
    assert!(!added_a[0].allow);
    assert!(engine.has_active_wfp_filter(exe_unbound, None, false));

    sender
        .send(SensorEvent::ProcessStop {
            pid: ident_a.pid,
            exit_time_100ns: unix_ms_to_filetime(1_760_007_000_200),
            exit_code: 0,
        })
        .await
        .expect("send ProcessStop A");
    wait_high_priority_processed(&engine, 2, "ProcessStop A cleanup").await;
    assert_eq!(defense.removed_wfp(), vec![added_a[0].handle]);
    assert!(!engine.has_active_wfp_filter(exe_unbound, None, false));

    // Part B: Outbound connect binds alert to pre-emptive block until operator triage resolves it.
    let ident_b = ProcessIdentity::new(5007, unix_ms_to_filetime(1_760_007_000_300));
    sender
        .send(SensorEvent::ProcessStart {
            identity: ident_b,
            parent_pid: 4,
            exe_path: exe_contained.to_string(),
            command_line: "moved_payload.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send ProcessStart B");
    wait_high_priority_processed(&engine, 3, "ProcessStart B pre-emptive WFP block").await;
    let added_b = defense.added_wfp();
    assert_eq!(added_b.len(), 2, "L-18 must install pre-emptive WFP block on ProcessStart B");
    assert_eq!(added_b[1].exe_path, exe_contained);
    assert_eq!(added_b[1].remote_ip, None);
    assert!(!added_b[1].allow);
    assert!(engine.has_active_wfp_filter(exe_contained, None, false));

    sender
        .send(SensorEvent::NetworkConnect {
            pid: ident_b.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77)),
            dst_port: 443,
            domain_hint: Some("exfil.example.invalid".to_string()),
            timestamp_ms: 1_760_007_000_500,
        })
        .await
        .expect("send NetworkConnect B");
    wait_high_priority_processed(&engine, 4, "NetworkConnect B containment").await;
    assert_eq!(defense.suspends(), vec![ident_b]);

    sender
        .send(SensorEvent::ProcessStop {
            pid: ident_b.pid,
            exit_time_100ns: unix_ms_to_filetime(1_760_007_001_000),
            exit_code: 0,
        })
        .await
        .expect("send ProcessStop B");
    wait_high_priority_processed(&engine, 5, "ProcessStop B while alert bound").await;
    assert!(
        engine.has_active_wfp_filter(exe_contained, None, false),
        "alert-bound pre-emptive WFP filter must stay active across ProcessStop until resolved"
    );

    let alerts = store.list_alerts(None, 10).expect("list alerts");
    let net_alert = alerts
        .iter()
        .find(|a| a.source_layer == "LAYER_3_NETWORK")
        .expect("outbound alert present");
    assert_eq!(net_alert.rule_id, "LEDR-NET-HIGH-RISK-PATH");
    assert_eq!(net_alert.severity, AlertSeverity::High);
    assert!(net_alert.process_suspended);
    let ctx: serde_json::Value = serde_json::from_str(&net_alert.context_json).expect("ctx json");
    assert_eq!(ctx.get("risk_class").and_then(|v| v.as_str()), Some("HighRiskPath"));
    assert_eq!(
        ctx.get("motw_source").and_then(|v| v.as_str()),
        Some("zone_identifier_ads")
    );

    engine
        .resolve_alert_with_outcome(
            &net_alert.alert_id,
            AlertDecision::TerminateAndBlock {
                add_block_rule: false,
            },
        )
        .expect("resolve bound outbound alert");
    assert_eq!(
        defense.removed_wfp(),
        vec![added_a[0].handle, added_b[1].handle]
    );
    assert!(!engine.has_active_wfp_filter(exe_contained, None, false));

    engine.shutdown_and_flush().await.expect("shutdown");
}

#[tokio::test]
async fn daemon_p4_08_l18_preemptive_wfp_respects_audit_mode_and_network_allow_block() {
    let exe_audit = r"C:\Tools\audit_motw.exe";
    let exe_allowed = r"C:\Tools\allowed_motw.exe";
    let sha_allowed = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    let motw_insp = Arc::new(MapMotwInspector::default());
    motw_insp.insert(
        exe_audit,
        MotwZoneInfo {
            zone_id: 3,
            host_url: Some("https://dl.example.invalid/audit_motw.exe".to_string()),
            referrer_url: None,
        },
    );
    motw_insp.insert(
        exe_allowed,
        MotwZoneInfo {
            zone_id: 3,
            host_url: Some("https://dl.example.invalid/allowed_motw.exe".to_string()),
            referrer_url: None,
        },
    );
    let bin_insp = Arc::new(MapBinaryInspector::default());
    bin_insp.insert(
        exe_allowed,
        BinaryIdentity {
            exe_path: exe_allowed.to_string(),
            sha256: Some(sha_allowed.to_string()),
            authenticode: None,
        },
    );

    // Part A: Audit mode never installs WFP block filters while still recording origin_url.
    let audit_defense = Arc::new(MockDefense::new());
    let audit_store = LedrStore::open_in_memory().expect("open audit store");
    let audit_engine = DaemonEngine::start_with_motw_inspector(
        audit_store.clone(),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::Audit,
            ..DaemonConfig::default()
        },
        audit_defense.clone(),
        Arc::new(RecordingNotifier::default()),
        bin_insp.clone(),
        Arc::new(NullLiveProcessInspector),
        motw_insp.clone(),
    );
    let id_audit = ProcessIdentity::new(5008, unix_ms_to_filetime(1_760_008_000_000));
    audit_engine
        .sender()
        .send(SensorEvent::ProcessStart {
            identity: id_audit,
            parent_pid: 4,
            exe_path: exe_audit.to_string(),
            command_line: "audit_motw.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send audit ProcessStart");
    audit_engine.shutdown_and_flush().await.expect("shutdown audit");
    assert!(audit_defense.added_wfp().is_empty());
    let audit_snap = audit_store
        .query_flight_recorder(10, Some(&id_audit.instance_id()))
        .expect("query audit proc");
    assert_eq!(
        audit_snap.processes[0].origin_url.as_deref(),
        Some("https://dl.example.invalid/audit_motw.exe")
    );

    // Part B: Existing app-wide NetworkAllow suppresses L-18 pre-emptive WFP block.
    let allow_defense = Arc::new(MockDefense::new());
    let allow_store = LedrStore::open_in_memory().expect("open allow store");
    allow_store
        .upsert_rule(&AllowlistRuleRecord {
            rule_id: "ALLOW-MOTW-TEST".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: exe_allowed.to_string(),
            sha256: Some(sha_allowed.to_string()),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: None,
            created_at_ms: 1_760_008_000_000,
            created_by: "user_triage".to_string(),
        })
        .expect("insert NetworkAllow rule");
    let allow_engine = DaemonEngine::start_with_motw_inspector(
        allow_store,
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::Enforce,
            ..DaemonConfig::default()
        },
        allow_defense.clone(),
        Arc::new(RecordingNotifier::default()),
        bin_insp,
        Arc::new(NullLiveProcessInspector),
        motw_insp,
    );
    let id_allowed = ProcessIdentity::new(5009, unix_ms_to_filetime(1_760_008_100_000));
    allow_engine
        .sender()
        .send(SensorEvent::ProcessStart {
            identity: id_allowed,
            parent_pid: 4,
            exe_path: exe_allowed.to_string(),
            command_line: "allowed_motw.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send allowed ProcessStart");
    wait_high_priority_processed(&allow_engine, 1, "allowed ProcessStart").await;
    assert!(
        !allow_engine.has_active_wfp_filter(exe_allowed, None, false),
        "existing app-wide NetworkAllow must suppress pre-emptive WFP block"
    );
    assert!(allow_engine.has_active_wfp_filter(exe_allowed, None, true));

    allow_engine.shutdown_and_flush().await.expect("shutdown allow");
}

#[tokio::test]
async fn daemon_p4_09_browser_event_severities_truncation_and_l19_no_toast_default() {
    let notifier_default = Arc::new(RecordingNotifier::default());
    let store = LedrStore::open_in_memory().expect("open store");
    let engine = DaemonEngine::start_with_motw_inspector(
        store.clone(),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default() // notify_browser_events defaults to false (L-19)
        },
        Arc::new(MockDefense::new()),
        notifier_default.clone(),
        Arc::new(MapBinaryInspector::default()),
        Arc::new(NullLiveProcessInspector),
        Arc::new(MapMotwInspector::default()),
    );

    assert!(!engine.config().notify_browser_events);

    // Multi-byte UTF-8 string exceeding 8 KiB (`MAX_BROWSER_EVENT_DETAILS_BYTES`).
    let big_details = "あ".repeat(3_000); // 9,000 bytes
    assert!(big_details.len() > MAX_BROWSER_EVENT_DETAILS_BYTES);

    let cases = [
        (
            BrowserSecurityEventType::ClickFixPastejacking,
            "https://clickfix.example.invalid/",
            Some(big_details.as_str()),
            AlertSeverity::High,
        ),
        (
            BrowserSecurityEventType::NrdPasswordWarning,
            "https://fresh-nrd.example.invalid/login",
            Some("NRD 3 days old"),
            AlertSeverity::High,
        ),
        (
            BrowserSecurityEventType::HomographWarning,
            "https://paypa1.example.invalid/auth",
            Some("Matched brand: paypal"),
            AlertSeverity::High,
        ),
        (
            BrowserSecurityEventType::DnrBlockedRequest,
            "https://c2-sim.example.invalid/beacon",
            None,
            AlertSeverity::Medium,
        ),
    ];

    for (idx, (ev_type, url, details, expected_sev)) in cases.iter().enumerate() {
        let outcome = engine
            .record_browser_event(*ev_type, url, *details, 1_760_009_000_000 + idx as i64)
            .expect("record browser event");
        let BrowserEventOutcome::Recorded(alert) = outcome else {
            panic!("expected Recorded outcome for {ev_type:?}");
        };
        assert_eq!(alert.severity, *expected_sev);
        assert_eq!(alert.source_layer, "LAYER_4_BROWSER");
        assert_eq!(alert.rule_id, format!("BROWSER-{ev_type:?}"));
        assert_eq!(alert.process_instance_id, None);
        assert!(!alert.process_suspended);
        if *ev_type == BrowserSecurityEventType::ClickFixPastejacking {
            let ctx: serde_json::Value =
                serde_json::from_str(&alert.context_json).expect("parse context");
            let stored_details = ctx
                .get("details")
                .and_then(|v| v.as_str())
                .expect("truncated details string");
            assert!(stored_details.len() <= MAX_BROWSER_EVENT_DETAILS_BYTES);
            assert_eq!(
                ctx.get("details_truncated").and_then(|v| v.as_bool()),
                Some(true)
            );
        }
    }

    assert!(
        notifier_default.alerts().is_empty(),
        "L-19: browser events must not trigger OS toast notifications by default"
    );

    // When notify_browser_events is explicitly enabled via config hook, toast fires.
    let notifier_enabled = Arc::new(RecordingNotifier::default());
    let engine_toast = DaemonEngine::start_with_motw_inspector(
        LedrStore::open_in_memory().expect("open store"),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            notify_browser_events: true,
            ..DaemonConfig::default()
        },
        Arc::new(MockDefense::new()),
        notifier_enabled.clone(),
        Arc::new(MapBinaryInspector::default()),
        Arc::new(NullLiveProcessInspector),
        Arc::new(MapMotwInspector::default()),
    );
    engine_toast
        .record_browser_event(
            BrowserSecurityEventType::ClickFixPastejacking,
            "https://toast.example.invalid/",
            None,
            1_760_009_000_500,
        )
        .expect("record with toast enabled");
    assert_eq!(notifier_enabled.alerts().len(), 1);

    engine.shutdown_and_flush().await.expect("shutdown default");
    engine_toast
        .shutdown_and_flush()
        .await
        .expect("shutdown toast");
}

#[tokio::test]
async fn daemon_p4_10_browser_event_30s_dedup_window_and_store_error_compensation() {
    let store = LedrStore::open_in_memory().expect("open store");
    let engine = DaemonEngine::start_with_motw_inspector(
        store.clone(),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        Arc::new(MockDefense::new()),
        Arc::new(RecordingNotifier::default()),
        Arc::new(MapBinaryInspector::default()),
        Arc::new(NullLiveProcessInspector),
        Arc::new(MapMotwInspector::default()),
    );

    let t0 = 1_760_010_000_000i64;
    assert!(matches!(
        engine
            .record_browser_event(
                BrowserSecurityEventType::ClickFixPastejacking,
                "HTTPS://Evil.Example/Page?A=1#sec1",
                Some("first"),
                t0,
            )
            .expect("first"),
        BrowserEventOutcome::Recorded(_)
    ));

    // Normalized URL (scheme/authority lowercased, fragment stripped) within 30s -> Deduplicated.
    assert_eq!(
        engine
            .record_browser_event(
                BrowserSecurityEventType::ClickFixPastejacking,
                "https://evil.example/Page?A=1#sec2",
                Some("duplicate"),
                t0 + 29_999,
            )
            .expect("within window"),
        BrowserEventOutcome::Deduplicated
    );

    // Different event type on the same URL -> Recorded.
    assert!(matches!(
        engine
            .record_browser_event(
                BrowserSecurityEventType::HomographWarning,
                "https://evil.example/Page?A=1",
                None,
                t0 + 100,
            )
            .expect("different type"),
        BrowserEventOutcome::Recorded(_)
    ));

    // At 30,000 ms boundary -> Recorded again.
    assert!(matches!(
        engine
            .record_browser_event(
                BrowserSecurityEventType::ClickFixPastejacking,
                "https://evil.example/Page?A=1",
                Some("after window"),
                t0 + 30_000,
            )
            .expect("after 30s window"),
        BrowserEventOutcome::Recorded(_)
    ));

    // Store failure compensation: failed persist must not consume the dedup slot!
    engine.set_fail_record_alert_for_test(true);
    let err = engine
        .record_browser_event(
            BrowserSecurityEventType::NrdPasswordWarning,
            "https://compensate.example.invalid/login",
            None,
            t0,
        )
        .expect_err("injected store failure");
    assert!(matches!(err, BrowserReportError::Store(_)));

    engine.set_fail_record_alert_for_test(false);
    assert!(matches!(
        engine
            .record_browser_event(
                BrowserSecurityEventType::NrdPasswordWarning,
                "https://compensate.example.invalid/login",
                None,
                t0 + 10,
            )
            .expect("retry after store failure compensation"),
        BrowserEventOutcome::Recorded(_)
    ));

    // Capacity bound (256 entries): pushing 256 additional distinct URLs evicts the first URL.
    for i in 0..256 {
        assert!(matches!(
            engine
                .record_browser_event(
                    BrowserSecurityEventType::DnrBlockedRequest,
                    &format!("https://cap-{i}.example.invalid/"),
                    None,
                    t0 + i,
                )
                .expect("capacity fill"),
            BrowserEventOutcome::Recorded(_)
        ));
    }
    assert!(matches!(
        engine
            .record_browser_event(
                BrowserSecurityEventType::ClickFixPastejacking,
                "https://evil.example/Page?A=1",
                None,
                t0 + 30_100,
            )
            .expect("evicted key can be recorded again"),
        BrowserEventOutcome::Recorded(_)
    ));

    engine.shutdown_and_flush().await.expect("shutdown");
}

#[tokio::test]
async fn daemon_p4_11_layer4_browser_alert_resolution_semantics() {
    let defense = Arc::new(MockDefense::new());
    let store = LedrStore::open_in_memory().expect("open store");
    let engine = DaemonEngine::start_with_motw_inspector(
        store,
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        defense.clone(),
        Arc::new(RecordingNotifier::default()),
        Arc::new(MapBinaryInspector::default()),
        Arc::new(NullLiveProcessInspector),
        Arc::new(MapMotwInspector::default()),
    );

    let BrowserEventOutcome::Recorded(alert1) = engine
        .record_browser_event(
            BrowserSecurityEventType::ClickFixPastejacking,
            "https://one.example.invalid/",
            None,
            1_760_011_000_000,
        )
        .expect("record alert1")
    else {
        panic!("expected recorded");
    };
    let BrowserEventOutcome::Recorded(alert2) = engine
        .record_browser_event(
            BrowserSecurityEventType::DnrBlockedRequest,
            "https://two.example.invalid/",
            None,
            1_760_011_000_100,
        )
        .expect("record alert2")
    else {
        panic!("expected recorded");
    };

    // AllowPermanent and TerminateAndBlock(add_block_rule: true) must reject without changing status.
    assert!(engine
        .resolve_alert_with_outcome(
            &alert1.alert_id,
            AlertDecision::AllowPermanent {
                use_signer_if_available: false,
                allow_dest: None,
            },
        )
        .is_err());
    assert!(engine
        .resolve_alert_with_outcome(
            &alert1.alert_id,
            AlertDecision::TerminateAndBlock {
                add_block_rule: true,
            },
        )
        .is_err());

    // AllowOnce resolves cleanly to ApprovedOnce without touching defense actuator.
    let res1 = engine
        .resolve_alert_with_outcome(&alert1.alert_id, AlertDecision::AllowOnce)
        .expect("AllowOnce resolves LAYER_4_BROWSER");
    assert_eq!(res1.alert.status, AlertStatus::ApprovedOnce);
    assert_eq!(res1.saved_rule_id, None);
    assert!(res1.alert.resolved_at_ms.is_some());

    // TerminateAndBlock(add_block_rule: false) resolves cleanly to TerminatedBlocked.
    let res2 = engine
        .resolve_alert_with_outcome(
            &alert2.alert_id,
            AlertDecision::TerminateAndBlock {
                add_block_rule: false,
            },
        )
        .expect("TerminateAndBlock without rule resolves LAYER_4_BROWSER");
    assert_eq!(res2.alert.status, AlertStatus::TerminatedBlocked);
    assert_eq!(res2.saved_rule_id, None);
    assert!(defense.added_wfp().is_empty());
    assert!(defense.suspends().is_empty());

    engine.shutdown_and_flush().await.expect("shutdown");
}

#[tokio::test]
async fn daemon_p4_12_ipc_bridge_auth_and_end_to_end_named_pipe_roundtrip() {
    // Part A: Pure identity boundary check for bridge signer / SHA-256 pinning.
    let valid_bridge = BinaryIdentity {
        exe_path: AUTHORIZED_BRIDGE_EXE_PATH.to_string(),
        sha256: Some("deadbeef".to_string()),
        authenticode: Some(AuthenticodeInfo {
            signer_subject: "CN=LocalEDR, O=LocalEDR".to_string(),
            root_thumbprint: "3B1EFD3A66EA28B16697394703A72CA340A05BD5".to_string(),
        }),
    };
    assert!(verify_caller_identity(
        Some(&valid_bridge),
        AUTHORIZED_BRIDGE_EXE_PATH,
        Some("DEADBEEF"),
        Some("CN=LocalEDR"),
        Some("3B1EFD3A66EA28B16697394703A72CA340A05BD5"),
        false,
    ));
    assert!(!verify_caller_identity(
        Some(&valid_bridge),
        AUTHORIZED_BRIDGE_EXE_PATH,
        Some("00000000"),
        None,
        None,
        false,
    ));

    // Part B: Named Pipe strict auth rejects test process for bridge commands.
    let strict_pipe = unique_test_pipe_name();
    let strict_engine = DaemonEngine::start(
        LedrStore::open_in_memory().expect("open strict store"),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: strict_pipe.clone(),
            dev_mode_bypass_ui_auth: false,
            authorized_bridge_sha256: Some("deadbeef".to_string()),
            ..DaemonConfig::default()
        },
    );
    let strict_handle = start_ipc_server(Arc::clone(&strict_engine)).expect("bind strict pipe");
    let pipe_for_strict = strict_pipe.clone();
    let (dl_unauth, ev_unauth) = tokio::task::spawn_blocking(move || {
        let dl = send_pipe_request(
            &pipe_for_strict,
            &IpcRequest::ReportDownloadOrigin {
                file_path: r"C:\Temp\drop.exe".to_string(),
                tab_url: "https://example.invalid/drop.exe".to_string(),
                frame_url: None,
                referrer_url: None,
                downloaded_at_ms: 1_760_012_000_000,
            },
        );
        let ev = send_pipe_request(
            &pipe_for_strict,
            &IpcRequest::ReportBrowserEvent {
                event_type: BrowserSecurityEventType::ClickFixPastejacking,
                url: "https://example.invalid/".to_string(),
                details: None,
                timestamp_ms: 1_760_012_000_100,
            },
        );
        (dl, ev)
    })
    .await
    .expect("strict client join");
    assert!(matches!(dl_unauth, IpcResponse::Error { ref code, .. } if code == "UNAUTHORIZED_CALLER"));
    assert!(matches!(ev_unauth, IpcResponse::Error { ref code, .. } if code == "UNAUTHORIZED_CALLER"));
    strict_handle.shutdown().await;
    strict_engine.shutdown_and_flush().await.expect("shutdown strict");

    // Part C: Dev bypass end-to-end Named Pipe roundtrip with real temp file + ADS.
    let dir = TestTempDir::new("p4-12");
    let dl_file = dir.0.join("pipe_dl.exe");
    std::fs::write(&dl_file, b"named-pipe-download-payload").expect("write dl file");
    write_zone_identifier(
        &dl_file,
        &MotwZoneInfo {
            zone_id: 3,
            host_url: Some("https://cdn.example.invalid/pipe_dl.exe".to_string()),
            referrer_url: Some("https://ads-ref.example.invalid/".to_string()),
        },
    )
    .expect("write ADS");
    let expected_sha = compute_file_sha256_hex(&dl_file).expect("sha256");

    let dev_pipe = unique_test_pipe_name();
    let dev_store = LedrStore::open_in_memory().expect("open dev store");
    let dev_engine = DaemonEngine::start(
        dev_store.clone(),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: dev_pipe.clone(),
            dev_mode_bypass_ui_auth: true,
            ..DaemonConfig::default()
        },
    );
    let dev_handle = start_ipc_server(Arc::clone(&dev_engine)).expect("bind dev pipe");
    let pipe_for_dev = dev_pipe.clone();
    let dl_path_str = dl_file.display().to_string();
    let (dl_ack, ev_ack) = tokio::task::spawn_blocking(move || {
        let dl = send_pipe_request(
            &pipe_for_dev,
            &IpcRequest::ReportDownloadOrigin {
                file_path: dl_path_str,
                tab_url: "https://tab.example.invalid/dl".to_string(),
                frame_url: None,
                referrer_url: None,
                downloaded_at_ms: 1_760_012_100_000,
            },
        );
        let ev = send_pipe_request(
            &pipe_for_dev,
            &IpcRequest::ReportBrowserEvent {
                event_type: BrowserSecurityEventType::HomographWarning,
                url: "https://micr0soft.example.invalid/login".to_string(),
                details: Some("Matched brand: microsoft".to_string()),
                timestamp_ms: 1_760_012_100_100,
            },
        );
        (dl, ev)
    })
    .await
    .expect("dev client join");

    assert!(matches!(dl_ack, IpcResponse::Ack { .. }));
    assert!(matches!(ev_ack, IpcResponse::Ack { .. }));
    dev_handle.shutdown().await;
    dev_engine.shutdown_and_flush().await.expect("shutdown dev");

    let snap = dev_store.query_flight_recorder(10, None).expect("query store");
    assert_eq!(snap.download_origins.len(), 1);
    assert_eq!(
        snap.download_origins[0].sha256.as_deref(),
        Some(expected_sha.as_str())
    );
    assert_eq!(
        snap.download_origins[0].referrer_url.as_deref(),
        Some("https://ads-ref.example.invalid/")
    );

    let alerts = dev_store.list_alerts(None, 10).expect("list alerts");
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].source_layer, "LAYER_4_BROWSER");
    assert_eq!(alerts[0].severity, AlertSeverity::High);
}

#[tokio::test(flavor = "current_thread")]
async fn daemon_p4_13_ipc_spawn_blocking_keeps_async_runtime_responsive() {
    let entered = Arc::new((Mutex::new(0usize), Condvar::new()));
    let released = Arc::new((Mutex::new(false), Condvar::new()));
    let completed = Arc::new((Mutex::new(0usize), Condvar::new()));
    let _release_guard = GateReleaseGuard(Arc::clone(&released));

    let blocking_motw = Arc::new(BlockingGateMotwInspector::new(
        Arc::clone(&entered),
        Arc::clone(&released),
        Arc::clone(&completed),
    ));

    let pipe_name = unique_test_pipe_name();
    let engine = DaemonEngine::start_with_motw_inspector(
        LedrStore::open_in_memory().expect("open store"),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: pipe_name.clone(),
            dev_mode_bypass_ui_auth: true,
            ..DaemonConfig::default()
        },
        Arc::new(MockDefense::new()),
        Arc::new(RecordingNotifier::default()),
        Arc::new(MapBinaryInspector::default()),
        Arc::new(NullLiveProcessInspector),
        blocking_motw,
    );
    let ipc_handle = start_ipc_server(Arc::clone(&engine)).expect("bind IPC pipe");

    let pipe_slow = pipe_name.clone();
    let slow_client = tokio::task::spawn_blocking(move || {
        send_pipe_request(
            &pipe_slow,
            &IpcRequest::ReportDownloadOrigin {
                file_path: r"C:\Temp\blocked_hash.exe".to_string(),
                tab_url: "https://slow.example.invalid/blocked.exe".to_string(),
                frame_url: None,
                referrer_url: None,
                downloaded_at_ms: 1_760_013_000_000,
            },
        )
    });

    // Deterministically wait until `record_browser_download_origin_async` has entered
    // `BlockingGateMotwInspector` on the dedicated MOTW I/O thread pool, then confirm the
    // current-thread Tokio runtime still drives concurrent `Ping` IPC requests immediately.
    let entered_wait = Arc::clone(&entered);
    tokio::task::spawn_blocking(move || wait_count_reached(&entered_wait, 1))
        .await
        .expect("join entered waiter");

    let pipe_ping = pipe_name.clone();
    let ping_resp = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::task::spawn_blocking(move || send_pipe_request(&pipe_ping, &IpcRequest::Ping)),
    )
    .await
    .expect("Ping must not stall while ReportDownloadOrigin blocks on spawn_blocking")
    .expect("join Ping client");
    assert!(matches!(ping_resp, IpcResponse::Pong { .. }));

    // Release the blocking gate and confirm the slow ReportDownloadOrigin completes cleanly.
    {
        let (lock, cvar) = &*released;
        let mut flag = lock.lock().expect("lock released");
        *flag = true;
        cvar.notify_all();
    }
    let slow_resp = slow_client.await.expect("join slow client");
    assert!(matches!(slow_resp, IpcResponse::Ack { .. }));

    ipc_handle.shutdown().await;
    engine.shutdown_and_flush().await.expect("shutdown");
}

#[tokio::test]
async fn daemon_p4_14_burst_with_motw_preserves_zero_hp_drop_and_memory_budget() {
    let store = LedrStore::open_in_memory().expect("open store");
    let engine = DaemonEngine::start_with_motw_inspector(
        store.clone(),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        Arc::new(MockDefense::new()),
        Arc::new(RecordingNotifier::default()),
        Arc::new(MapBinaryInspector::default()),
        Arc::new(NullLiveProcessInspector),
        Arc::new(MapMotwInspector::default()),
    );

    engine
        .record_browser_download_origin(
            r"C:\Users\alice\Downloads\burst_dl.exe",
            "https://burst.example.invalid/burst_dl.exe",
            None,
            None,
            1_760_014_000_000,
        )
        .expect("seed download origin");

    let sender = engine.sender();
    let base_ft = unix_ms_to_filetime(1_760_014_001_000);
    for i in 0..2_000u32 {
        let exe = if i % 10 == 0 {
            r"C:\Users\alice\Downloads\burst_dl.exe"
        } else {
            r"C:\Windows\System32\svchost.exe"
        };
        sender
            .send(SensorEvent::ProcessStart {
                identity: ProcessIdentity::new(10_000 + i, base_ft + u64::from(i)),
                parent_pid: 4,
                exe_path: exe.to_string(),
                command_line: format!("proc {i}"),
                user_sid: None,
            })
            .await
            .expect("send ProcessStart");
    }

    engine.shutdown_and_flush().await.expect("shutdown");

    assert_eq!(engine.high_priority_dropped(), 0);
    assert_eq!(engine.metrics().high_priority_processed, 2_000);

    let channel_struct_bytes =
        (HIGH_PRIORITY_CHANNEL_CAPACITY + TELEMETRY_CHANNEL_CAPACITY) * size_of::<SensorEvent>();
    let proc_table_bytes = ACTIVE_PROCESS_TABLE_CAPACITY * size_of::<ActiveProcessEntry>();
    let total_bounded_bytes = channel_struct_bytes + proc_table_bytes;
    assert!(
        total_bounded_bytes <= 20 * 1024 * 1024,
        "bounded buffer baseline {total_bounded_bytes} bytes exceeds 20 MB budget"
    );
}

#[tokio::test]
async fn daemon_p4_15_stage1_verifies_current_binary_hash_and_falls_back_on_replacement() {
    let dir = TestTempDir::new("p4-15");
    let target_path = dir.0.join("replaced_tool.exe");
    let other_path = dir.0.join("other_dl.exe");

    std::fs::write(&target_path, b"original-downloaded-binary-v1").expect("write v1");
    let stage2_payload = b"different-downloaded-binary-v3-content-for-stage2";
    std::fs::write(&other_path, stage2_payload).expect("write stage2 payload");
    let expected_stage2_sha = compute_file_sha256_hex(&other_path).expect("sha stage2");

    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockDefense::new());
    let engine = DaemonEngine::start_with_motw_inspector(
        store.clone(),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        defense.clone(),
        Arc::new(RecordingNotifier::default()),
        Arc::new(WindowsBinaryInspector::new()),
        Arc::new(NullLiveProcessInspector),
        Arc::new(WindowsMotwInspector::new()),
    );

    let target_str = target_path.display().to_string();
    engine
        .record_browser_download_origin(
            &target_str,
            "https://dl-v1.example.invalid/tool.exe",
            None,
            Some("https://ref-v1.example.invalid/"),
            1_760_015_000_000,
        )
        .expect("record v1");

    // 1. Replace binary at same path with clean clean build (no ADS) -> Stage 1 must reject!
    std::fs::write(&target_path, b"clean-rebuilt-binary-no-ads-v2-different-length")
        .expect("overwrite with v2 clean");
    assert_eq!(
        engine.resolve_process_motw(&target_str, None, false),
        None,
        "replaced binary without matching hash or ADS must not inherit stale Stage 1 URL"
    );

    let sender = engine.sender();
    let base_ms = 1_760_015_001_000i64;
    let ident_a = ProcessIdentity::new(8001, unix_ms_to_filetime(base_ms));
    sender
        .send(SensorEvent::ProcessStart {
            identity: ident_a,
            parent_pid: 4,
            exe_path: target_str.clone(),
            command_line: "replaced_tool.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send ProcessStart clean replacement");
    wait_high_priority_processed(&engine, 1, "clean replacement ProcessStart").await;
    store.flush_batch().expect("flush clean replacement");

    let snap_a = store
        .query_flight_recorder(10, Some(&ident_a.instance_id()))
        .expect("query clean replacement");
    assert_eq!(snap_a.processes.len(), 1);
    assert_eq!(snap_a.processes[0].origin_url, None);
    assert_eq!(snap_a.processes[0].sha256, None);

    // Subcheck on a GeneralUnknown path (`C:\Tools\portable\...`, outside HighRiskPath `%TEMP%`):
    // replaced clean binary without ADS must also avoid L-18 MOTW pre-emptive WFP block.
    let general_exe = r"C:\Tools\portable\replaced_general.exe";
    let gen_v1_sha = "1111111111111111111111111111111111111111111111111111111111111111";
    let gen_v2_sha = "2222222222222222222222222222222222222222222222222222222222222222";
    let gen_bin = Arc::new(MapBinaryInspector::default());
    gen_bin.insert(
        general_exe,
        BinaryIdentity {
            exe_path: general_exe.to_string(),
            sha256: Some(gen_v1_sha.to_string()),
            authenticode: None,
        },
    );
    let gen_defense = Arc::new(MockDefense::new());
    let gen_store = LedrStore::open_in_memory().expect("open gen store");
    let gen_engine = DaemonEngine::start_with_motw_inspector(
        gen_store.clone(),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        gen_defense.clone(),
        Arc::new(RecordingNotifier::default()),
        gen_bin.clone(),
        Arc::new(NullLiveProcessInspector),
        Arc::new(MapMotwInspector::default()),
    );
    gen_engine
        .record_browser_download_origin(
            general_exe,
            "https://dl-gen.example.invalid/v1.exe",
            None,
            None,
            1_760_015_000_500,
        )
        .expect("record general v1");
    gen_bin.insert(
        general_exe,
        BinaryIdentity {
            exe_path: general_exe.to_string(),
            sha256: Some(gen_v2_sha.to_string()),
            authenticode: None,
        },
    );
    let ident_gen = ProcessIdentity::new(8091, unix_ms_to_filetime(base_ms));
    gen_engine
        .sender()
        .send(SensorEvent::ProcessStart {
            identity: ident_gen,
            parent_pid: 4,
            exe_path: general_exe.to_string(),
            command_line: "replaced_general.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send general ProcessStart");
    wait_high_priority_processed(&gen_engine, 1, "general clean replacement").await;
    assert!(
        gen_defense.added_wfp().is_empty(),
        "replaced non-MOTW GeneralUnknown binary must not receive L-18 pre-emptive WFP block"
    );
    gen_engine.shutdown_and_flush().await.expect("shutdown gen");

    // 2. Register `other_path` (stage2_payload), then overwrite `target_path` with `stage2_payload`:
    //    Stage 1 path match rejects old dl-v1 URL and falls back to Stage 2 hash match without re-hashing.
    engine
        .record_browser_download_origin(
            &other_path.display().to_string(),
            "https://stage2-v3.example.invalid/other.exe",
            None,
            Some("https://ref-v3.example.invalid/"),
            1_760_015_002_000,
        )
        .expect("record v3 stage2");
    std::fs::write(&target_path, stage2_payload).expect("overwrite with v3 payload");
    let stage2_attr = engine
        .resolve_process_motw(&target_str, None, false)
        .expect("Stage 2 fallback match");
    assert_eq!(stage2_attr.stage, MotwMatchStage::DownloadSha256);
    assert_eq!(
        stage2_attr.origin_url,
        "https://stage2-v3.example.invalid/other.exe"
    );
    assert_eq!(
        stage2_attr.sha256.as_deref(),
        Some(expected_stage2_sha.as_str())
    );

    let ident_b = ProcessIdentity::new(8002, unix_ms_to_filetime(base_ms + 1_000));
    sender
        .send(SensorEvent::ProcessStart {
            identity: ident_b,
            parent_pid: 4,
            exe_path: target_str.clone(),
            command_line: "replaced_tool.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send ProcessStart stage2 fallback");
    wait_high_priority_processed(&engine, 2, "stage2 fallback ProcessStart").await;
    assert!(
        !defense.added_wfp().is_empty(),
        "Stage 2 fallback MOTW binary should receive L-18 pre-emptive WFP block"
    );

    // 3. Overwrite with unregistered payload carrying ZoneId=3 ADS -> Stage 3 fallback.
    std::fs::write(&target_path, b"unregistered-ads-binary-v4").expect("overwrite v4");
    write_zone_identifier(
        &target_path,
        &MotwZoneInfo {
            zone_id: 3,
            host_url: Some("https://ads-v4.example.invalid/v4.exe".to_string()),
            referrer_url: Some("https://ref-v4.example.invalid/".to_string()),
        },
    )
    .expect("write ZoneId=3 ADS");
    let stage3_attr = engine
        .resolve_process_motw(&target_str, None, false)
        .expect("Stage 3 fallback match");
    assert_eq!(stage3_attr.stage, MotwMatchStage::ZoneIdentifierAds);
    assert_eq!(
        stage3_attr.origin_url,
        "https://ads-v4.example.invalid/v4.exe"
    );
    assert_eq!(stage3_attr.sha256, None);

    engine.shutdown_and_flush().await.expect("shutdown");

    // 4. Oversized replacement over a hashed Stage 1 download rejects Stage 1 and skips Stage 2.
    let small_to_large = dir.0.join("grew_oversized.exe");
    std::fs::write(&small_to_large, b"tiny-v1").expect("write small binary");
    let capped_engine = DaemonEngine::start_with_motw_inspector(
        LedrStore::open_in_memory().expect("open capped store"),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            download_hash_max_bytes: 16,
            ..DaemonConfig::default()
        },
        Arc::new(MockDefense::new()),
        Arc::new(RecordingNotifier::default()),
        Arc::new(WindowsBinaryInspector::new()),
        Arc::new(NullLiveProcessInspector),
        Arc::new(WindowsMotwInspector::new()),
    );
    let large_str = small_to_large.display().to_string();
    capped_engine
        .record_browser_download_origin(
            &large_str,
            "https://small.example.invalid/tiny.exe",
            None,
            None,
            1_760_015_010_000,
        )
        .expect("record small hashed binary");
    std::fs::write(&small_to_large, vec![b'X'; 64]).expect("overwrite with oversized >16B file");
    assert_eq!(
        capped_engine.resolve_process_motw(&large_str, None, false),
        None
    );
    write_zone_identifier(
        &small_to_large,
        &MotwZoneInfo {
            zone_id: 3,
            host_url: Some("https://oversized-ads.example.invalid/big.exe".to_string()),
            referrer_url: None,
        },
    )
    .expect("write oversized ADS");
    let oversized_stage3 = capped_engine
        .resolve_process_motw(&large_str, None, false)
        .expect("oversized falls back to Stage 3 ADS");
    assert_eq!(oversized_stage3.stage, MotwMatchStage::ZoneIdentifierAds);
    assert_eq!(
        oversized_stage3.origin_url,
        "https://oversized-ads.example.invalid/big.exe"
    );
    capped_engine
        .shutdown_and_flush()
        .await
        .expect("shutdown capped");
}

#[tokio::test]
async fn daemon_p4_16_blocked_motw_io_does_not_stall_pipeline_late_backfill_and_clean_shutdown() {
    let entered = Arc::new((Mutex::new(0usize), Condvar::new()));
    let released = Arc::new((Mutex::new(false), Condvar::new()));
    let completed = Arc::new((Mutex::new(0usize), Condvar::new()));
    let _release_guard = GateReleaseGuard(Arc::clone(&released));

    let gated_motw = Arc::new(BlockingGateMotwInspector {
        entered: Arc::clone(&entered),
        released: Arc::clone(&released),
        completed: Arc::clone(&completed),
        target_substring: Some("hung-server".to_string()),
        return_zone: Some(MotwZoneInfo {
            zone_id: 3,
            host_url: Some("https://late-ads.example.invalid/slow.exe".to_string()),
            referrer_url: Some("https://ref-late.example.invalid/".to_string()),
        }),
    });

    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockDefense::new());
    let engine = DaemonEngine::start_with_motw_inspector(
        store.clone(),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            motw_sync_wait_budget_ms: 25,
            ..DaemonConfig::default()
        },
        defense.clone(),
        Arc::new(RecordingNotifier::default()),
        Arc::new(MapBinaryInspector::default()),
        Arc::new(NullLiveProcessInspector),
        gated_motw,
    );

    let sender = engine.sender();
    let t0_ms = 1_760_016_000_000i64;
    let exited_exe = r"\\hung-server\share\exited_slow.exe";
    let active_exe = r"\\hung-server\share\active_slow.exe";
    let exited_ident = ProcessIdentity::new(8101, unix_ms_to_filetime(t0_ms));
    let active_ident = ProcessIdentity::new(8102, unix_ms_to_filetime(t0_ms + 10));
    let canary_ident = ProcessIdentity::new(8103, unix_ms_to_filetime(t0_ms + 20));

    // Saturate both raw-OS MOTW worker threads on hung SMB paths (`exited_slow` then `active_slow`).
    sender
        .send(SensorEvent::ProcessStart {
            identity: exited_ident,
            parent_pid: 4,
            exe_path: exited_exe.to_string(),
            command_line: "exited_slow.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send exited_slow ProcessStart");
    sender
        .send(SensorEvent::ProcessStart {
            identity: active_ident,
            parent_pid: 4,
            exe_path: active_exe.to_string(),
            command_line: "active_slow.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send active_slow ProcessStart");
    // Stop PID 8101 before the MOTW I/O gate opens so its late attribution still backfills
    // SQLite history (`COALESCE`) while avoiding any late active-defense WFP block.
    sender
        .send(SensorEvent::ProcessStop {
            pid: exited_ident.pid,
            exit_code: 0,
            exit_time_100ns: unix_ms_to_filetime(t0_ms + 50),
        })
        .await
        .expect("send exited_slow ProcessStop");
    // Send an unrelated process + CanaryFileAccess while BOTH MOTW workers remain wedged!
    sender
        .send(SensorEvent::ProcessStart {
            identity: canary_ident,
            parent_pid: 4,
            exe_path: r"C:\Temp\canary_probe.exe".to_string(),
            command_line: "canary_probe.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send canary_probe ProcessStart");
    sender
        .send(SensorEvent::CanaryFileAccess {
            pid: canary_ident.pid,
            target_path: r"C:\Temp\!00_LocalEDR_Canary_DoNotEdit.docx".to_string(),
            category: CanaryCategory::Honeypot,
            access_mask: 2,
            is_write_or_delete: true,
            timestamp_ms: t0_ms + 60,
        })
        .await
        .expect("send CanaryFileAccess");

    // Verify CanaryFileAccess alert fires promptly WITHOUT waiting on wedged MOTW workers.
    let canary_deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let alerts = store.list_alerts(None, 10).expect("list alerts");
        if alerts.iter().any(|a| a.source_layer == "LAYER_1_CANARY") {
            break;
        }
        assert!(
            Instant::now() < canary_deadline,
            "CanaryFileAccess stalled behind blocked MOTW I/O"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // Wait until both wedged MOTW workers have entered the gate, then open the gate.
    let entered_wait = Arc::clone(&entered);
    tokio::task::spawn_blocking(move || wait_count_reached(&entered_wait, 2))
        .await
        .expect("wait both workers in gate");
    {
        let (lock, cvar) = &*released;
        let mut flag = lock.lock().expect("lock released");
        *flag = true;
        cvar.notify_all();
    }

    // Active process (`8102`) receives late backfill (table/SQLite + L-18 pre-emptive WFP block),
    // and enqueue a third sentinel after opening the gate to ensure `exited_slow` has drained too.
    let sentinel_ident = ProcessIdentity::new(8104, unix_ms_to_filetime(t0_ms + 100));
    sender
        .send(SensorEvent::ProcessStart {
            identity: sentinel_ident,
            parent_pid: 4,
            exe_path: r"\\hung-server\share\sentinel_after.exe".to_string(),
            command_line: "sentinel_after.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send sentinel_after ProcessStart");

    let backfill_deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let _ = store.flush_batch();
        let active_snap = store
            .query_flight_recorder(10, Some(&active_ident.instance_id()))
            .expect("query active_slow");
        let exited_snap = store
            .query_flight_recorder(10, Some(&exited_ident.instance_id()))
            .expect("query exited_slow");
        let wfp_calls = defense.added_wfp();
        let active_backfilled = active_snap
            .processes
            .first()
            .and_then(|p| p.origin_url.as_deref())
            == Some("https://late-ads.example.invalid/slow.exe")
            && wfp_calls.iter().any(|c| c.exe_path.ends_with("active_slow.exe"));
        let exited_backfilled = exited_snap.processes.first().is_some_and(|p| {
            p.origin_url.as_deref() == Some("https://late-ads.example.invalid/slow.exe")
                && p.exited_at_ms.is_some()
        });
        let sentinel_backfilled = store
            .query_flight_recorder(10, Some(&sentinel_ident.instance_id()))
            .expect("query sentinel")
            .processes
            .first()
            .and_then(|p| p.origin_url.as_deref())
            .is_some();
        if active_backfilled && exited_backfilled && sentinel_backfilled {
            break;
        }
        assert!(
            Instant::now() < backfill_deadline,
            "timed out waiting for late MOTW backfill and L-18 WFP block"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let exited_snap = store
        .query_flight_recorder(10, Some(&exited_ident.instance_id()))
        .expect("query exited_slow");
    assert_eq!(exited_snap.processes.len(), 1);
    assert_eq!(
        exited_snap.processes[0].origin_url.as_deref(),
        Some("https://late-ads.example.invalid/slow.exe"),
        "already-exited process must still backfill SQLite origin_url history"
    );
    assert!(
        exited_snap.processes[0].exited_at_ms.is_some(),
        "already-exited process must preserve exited_at_ms after late MOTW history backfill"
    );
    assert!(
        !defense
            .added_wfp()
            .iter()
            .any(|c| c.exe_path.ends_with("exited_slow.exe")),
        "already-exited process must not receive late WFP block"
    );

    engine.shutdown_and_flush().await.expect("shutdown engine1");
    assert!(
        !defense
            .added_wfp()
            .iter()
            .any(|c| c.exe_path.ends_with("exited_slow.exe")),
        "already-exited process must still have zero WFP blocks after full pipeline drain"
    );

    // Part 2: Verify `shutdown_and_flush` detaches a permanently wedged raw-OS MOTW worker thread
    // within `shutdown_flush_timeout_ms` without hanging Tokio `Runtime::drop`.
    let entered2 = Arc::new((Mutex::new(0usize), Condvar::new()));
    let released2 = Arc::new((Mutex::new(false), Condvar::new()));
    let completed2 = Arc::new((Mutex::new(0usize), Condvar::new()));
    let _release_guard2 = GateReleaseGuard(Arc::clone(&released2));

    let wedged_engine = DaemonEngine::start_with_motw_inspector(
        LedrStore::open_in_memory().expect("open store2"),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            motw_sync_wait_budget_ms: 20,
            shutdown_flush_timeout_ms: 200,
            ..DaemonConfig::default()
        },
        Arc::new(MockDefense::new()),
        Arc::new(RecordingNotifier::default()),
        Arc::new(MapBinaryInspector::default()),
        Arc::new(NullLiveProcessInspector),
        Arc::new(BlockingGateMotwInspector::new(
            Arc::clone(&entered2),
            Arc::clone(&released2),
            Arc::clone(&completed2),
        )),
    );
    wedged_engine
        .sender()
        .send(SensorEvent::ProcessStart {
            identity: ProcessIdentity::new(8105, unix_ms_to_filetime(t0_ms + 200)),
            parent_pid: 4,
            exe_path: r"\\hung-server\share\wedged_forever.exe".to_string(),
            command_line: "wedged_forever.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send wedged ProcessStart");

    let entered2_wait = Arc::clone(&entered2);
    tokio::task::spawn_blocking(move || wait_count_reached(&entered2_wait, 1))
        .await
        .expect("wait wedged worker in gate");

    let shutdown_t0 = Instant::now();
    wedged_engine
        .shutdown_and_flush()
        .await
        .expect("shutdown must detach wedged MOTW worker cleanly");
    assert!(
        shutdown_t0.elapsed() < Duration::from_secs(2),
        "shutdown took {:?} with wedged MOTW worker",
        shutdown_t0.elapsed()
    );
}

#[tokio::test]
async fn daemon_p4_17_stage2_cache_generation_invalidation_and_ttl_purge_flag_reset() {
    let dir = TestTempDir::new("p4-17");
    let tool_path = dir.0.join("repeat_binary.exe");
    let expired_dl_1 = dir.0.join("expired_dl_1.exe");
    let expired_dl_2 = dir.0.join("expired_dl_2.exe");
    let after_purge_path = dir.0.join("after_purge.exe");
    std::fs::write(&tool_path, b"repeated-launch-binary-content").expect("write repeat binary");
    std::fs::write(&after_purge_path, b"post-purge-binary-content").expect("write post-purge binary");

    let counting_insp = Arc::new(CountingBinaryInspector::default());
    let engine = DaemonEngine::start_with_motw_inspector(
        LedrStore::open_in_memory().expect("open store"),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        Arc::new(MockDefense::new()),
        Arc::new(RecordingNotifier::default()),
        counting_insp.clone(),
        Arc::new(NullLiveProcessInspector),
        Arc::new(WindowsMotwInspector::new()),
    );

    assert!(!engine.has_download_origins_cached());

    // Record an expired download origin (>30 days old) for an unrelated path.
    let now_ms = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_millis(),
    )
    .expect("i64 ms");
    let expired_ts = now_ms - 40 * 86_400_000;
    engine
        .record_browser_download_origin(
            &expired_dl_1.display().to_string(),
            "https://old1.example.invalid/a.exe",
            None,
            None,
            expired_ts,
        )
        .expect("record expired download 1");
    assert!(engine.has_download_origins_cached());

    let tool_str = tool_path.display().to_string();
    assert_eq!(engine.motw_stage2_cache_hits(), 0);
    assert_eq!(engine.resolve_process_motw(&tool_str, None, false), None);
    assert_eq!(counting_insp.sha256_calls(), 1);
    assert_eq!(
        counting_insp.inspect_calls(),
        0,
        "MOTW hot path must use lightweight compute_sha256 without Authenticode inspect()"
    );
    assert_eq!(engine.motw_stage2_cache_hits(), 0);

    // Repeat launch of unchanged binary recomputes lightweight SHA-256 (no Authenticode)
    // and hits the bounded Stage 2 `(sha256, generation)` SQLite lookup cache.
    assert_eq!(engine.resolve_process_motw(&tool_str, None, false), None);
    assert_eq!(counting_insp.sha256_calls(), 2);
    assert_eq!(counting_insp.inspect_calls(), 0);
    assert_eq!(engine.motw_stage2_cache_hits(), 1);

    // New download increments generation and invalidates the Stage 2 lookup cache.
    engine
        .record_browser_download_origin(
            &expired_dl_2.display().to_string(),
            "https://old2.example.invalid/b.exe",
            None,
            None,
            expired_ts + 1_000,
        )
        .expect("record expired download 2");
    assert_eq!(engine.resolve_process_motw(&tool_str, None, false), None);
    assert_eq!(counting_insp.sha256_calls(), 3);
    assert_eq!(
        engine.motw_stage2_cache_hits(),
        1,
        "new download generation must miss previous Stage 2 cache entry"
    );
    // Next launch under the new generation populates and hits the cache again.
    assert_eq!(engine.resolve_process_motw(&tool_str, None, false), None);
    assert_eq!(counting_insp.sha256_calls(), 4);
    assert_eq!(engine.motw_stage2_cache_hits(), 2);

    // TTL purge removing all download_origins rows resets `has_download_origins_cached` to false.
    let purged = engine.run_ttl_purge_once().expect("run TTL purge");
    assert_eq!(purged.downloads_deleted, 2);
    assert!(
        !engine.has_download_origins_cached(),
        "has_download_origins flag must reset to false after TTL purge empties download_origins"
    );

    // Once reset, launching a brand-new binary does zero Stage 2 hashing.
    assert_eq!(
        engine.resolve_process_motw(&after_purge_path.display().to_string(), None, false),
        None
    );
    assert_eq!(counting_insp.sha256_calls(), 4);

    // Direct smoke check of `WindowsBinaryInspector::compute_sha256`.
    let expected_tool_sha = compute_file_sha256_hex(&tool_path).expect("expected sha");
    assert_eq!(
        WindowsBinaryInspector::new()
            .compute_sha256(&tool_str)
            .as_deref(),
        Some(expected_tool_sha.as_str())
    );

    engine.shutdown_and_flush().await.expect("shutdown");
}

#[tokio::test]
async fn daemon_p4_18_ipc_download_timeout_cancels_write_and_retry_is_idempotent() {
    // Part A: IPC session timeout cancels in-flight ReportDownloadOrigin before SQLite write.
    let entered = Arc::new((Mutex::new(0usize), Condvar::new()));
    let released = Arc::new((Mutex::new(false), Condvar::new()));
    let completed = Arc::new((Mutex::new(0usize), Condvar::new()));
    let _release_guard = GateReleaseGuard(Arc::clone(&released));

    let pipe_timeout = unique_test_pipe_name();
    let store_timeout = LedrStore::open_in_memory().expect("open timeout store");
    let engine_timeout = DaemonEngine::start_with_motw_inspector(
        store_timeout.clone(),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: pipe_timeout.clone(),
            ipc_session_timeout_ms: 150,
            shutdown_flush_timeout_ms: 200,
            dev_mode_bypass_ui_auth: true,
            ..DaemonConfig::default()
        },
        Arc::new(MockDefense::new()),
        Arc::new(RecordingNotifier::default()),
        Arc::new(MapBinaryInspector::default()),
        Arc::new(NullLiveProcessInspector),
        Arc::new(BlockingGateMotwInspector::new(
            Arc::clone(&entered),
            Arc::clone(&released),
            Arc::clone(&completed),
        )),
    );
    let ipc_timeout = start_ipc_server(Arc::clone(&engine_timeout)).expect("bind timeout pipe");

    let pipe_req = pipe_timeout.clone();
    let client_res = tokio::task::spawn_blocking(move || {
        try_send_pipe_request(
            &pipe_req,
            &IpcRequest::ReportDownloadOrigin {
                file_path: r"C:\Temp\timed_out_download.exe".to_string(),
                tab_url: "https://timeout.example.invalid/file.exe".to_string(),
                frame_url: None,
                referrer_url: None,
                downloaded_at_ms: 1_760_018_000_000,
            },
        )
    })
    .await
    .expect("join timeout client");
    assert!(
        matches!(
            client_res,
            Err(FrameError::Io(ref e))
                if matches!(
                    e.kind(),
                    ErrorKind::UnexpectedEof | ErrorKind::BrokenPipe | ErrorKind::ConnectionReset
                )
        ) || matches!(client_res, Err(FrameError::TruncatedFrame { .. })),
        "timed out ReportDownloadOrigin must close pipe cleanly: {client_res:?}"
    );

    // Release gate and wait deterministically for the cancelled MOTW job to finish cleanly.
    {
        let (lock, cvar) = &*released;
        let mut flag = lock.lock().expect("lock released");
        *flag = true;
        cvar.notify_all();
    }
    let completed_wait = Arc::clone(&completed);
    tokio::task::spawn_blocking(move || wait_count_reached(&completed_wait, 1))
        .await
        .expect("wait completed");

    ipc_timeout.shutdown().await;
    engine_timeout
        .shutdown_and_flush()
        .await
        .expect("shutdown timeout engine");

    let snap_timeout = store_timeout
        .query_flight_recorder(10, None)
        .expect("query timeout store");
    assert!(
        snap_timeout.download_origins.is_empty(),
        "cancelled ReportDownloadOrigin must not commit late SQLite rows"
    );

    // Part B: Retrying identical ReportDownloadOrigin over IPC is idempotent (single DB row).
    let dir = TestTempDir::new("p4-18");
    let dl_file = dir.0.join("RetrySame.exe");
    std::fs::write(&dl_file, b"idempotent-download-payload").expect("write retry payload");

    let pipe_retry = unique_test_pipe_name();
    let store_retry = LedrStore::open_in_memory().expect("open retry store");
    let engine_retry = DaemonEngine::start(
        store_retry.clone(),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: pipe_retry.clone(),
            dev_mode_bypass_ui_auth: true,
            ..DaemonConfig::default()
        },
    );
    let ipc_retry = start_ipc_server(Arc::clone(&engine_retry)).expect("bind retry pipe");

    let canonical_path = dl_file.display().to_string();
    let alt_case_path = format!(r"\\?\{}", canonical_path.replace('\\', "/").to_ascii_lowercase());
    let (r1, r2) = tokio::task::spawn_blocking(move || {
        let first = send_pipe_request(
            &pipe_retry,
            &IpcRequest::ReportDownloadOrigin {
                file_path: canonical_path,
                tab_url: "https://retry.example.invalid/tool.exe".to_string(),
                frame_url: None,
                referrer_url: Some("https://ref.example.invalid/".to_string()),
                downloaded_at_ms: 1_760_018_500_000,
            },
        );
        let retry = send_pipe_request(
            &pipe_retry,
            &IpcRequest::ReportDownloadOrigin {
                file_path: alt_case_path,
                tab_url: "https://retry.example.invalid/tool.exe".to_string(),
                frame_url: None,
                referrer_url: None,
                downloaded_at_ms: 1_760_018_500_000,
            },
        );
        (first, retry)
    })
    .await
    .expect("join retry client");
    assert!(matches!(r1, IpcResponse::Ack { .. }));
    assert!(matches!(r2, IpcResponse::Ack { .. }));

    ipc_retry.shutdown().await;
    engine_retry
        .shutdown_and_flush()
        .await
        .expect("shutdown retry engine");

    let snap_retry = store_retry
        .query_flight_recorder(10, None)
        .expect("query retry store");
    assert_eq!(
        snap_retry.download_origins.len(),
        1,
        "identical download retry must deduplicate instead of inserting duplicate rows"
    );
}

#[tokio::test]
async fn daemon_p4_19_late_motw_escalates_observed_process_to_enforced_containment_once() {
    let entered = Arc::new((Mutex::new(0usize), Condvar::new()));
    let released = Arc::new((Mutex::new(false), Condvar::new()));
    let completed = Arc::new((Mutex::new(0usize), Condvar::new()));
    let _release_guard = GateReleaseGuard(Arc::clone(&released));

    let exe_path = r"C:\Tools\portable.exe";
    let gated_motw = Arc::new(BlockingGateMotwInspector {
        entered: Arc::clone(&entered),
        released: Arc::clone(&released),
        completed: Arc::clone(&completed),
        target_substring: Some("portable.exe".to_string()),
        return_zone: Some(MotwZoneInfo {
            zone_id: 3,
            host_url: Some("https://late-escalate.example.invalid/portable.exe".to_string()),
            referrer_url: Some("https://ref-escalate.example.invalid/".to_string()),
        }),
    });

    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockDefense::new());
    let notifier = Arc::new(RecordingNotifier::default());
    let engine = DaemonEngine::start_with_motw_inspector(
        store.clone(),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::PreemptiveOnly,
            motw_sync_wait_budget_ms: 20,
            ..DaemonConfig::default()
        },
        defense.clone(),
        notifier.clone(),
        Arc::new(MapBinaryInspector::default()),
        Arc::new(NullLiveProcessInspector),
        gated_motw,
    );

    let sender = engine.classified_sender();
    let t0_ms = 1_760_019_000_000i64;
    let ident = ProcessIdentity::new(9101, unix_ms_to_filetime(t0_ms));

    // 1. Start a GeneralUnknown executable while its MOTW lookup is blocked past the sync budget.
    sender
        .send(SensorEvent::ProcessStart {
            identity: ident,
            parent_pid: 4,
            exe_path: exe_path.to_string(),
            command_line: "portable.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send ProcessStart");
    wait_high_priority_processed(&engine, 1, "portable ProcessStart").await;

    let entered_wait = Arc::clone(&entered);
    tokio::task::spawn_blocking(move || wait_count_reached(&entered_wait, 1))
        .await
        .expect("wait worker in MOTW gate");
    assert!(
        defense.added_wfp().is_empty(),
        "GeneralUnknown binary must not have WFP block before MOTW resolves"
    );

    // 2. First outbound connect BEFORE MOTW resolves records an observe-only alert (`NET_OUTBOUND_OBSERVE`).
    sender
        .send(SensorEvent::NetworkConnect {
            pid: ident.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 71)),
            dst_port: 443,
            domain_hint: Some("obs1.example.invalid".to_string()),
            timestamp_ms: t0_ms + 100,
        })
        .await
        .expect("send first observe NetworkConnect");
    wait_high_priority_processed(&engine, 2, "first observe NetworkConnect").await;

    let pre_alerts = store.list_alerts(None, 10).expect("list pre-MOTW alerts");
    assert_eq!(pre_alerts.len(), 1, "expected 1 observe-only alert");
    assert!(
        !pre_alerts[0].process_suspended,
        "observe-only alert must not suspend process"
    );
    assert!(defense.suspends().is_empty());
    assert!(
        notifier.alerts().is_empty(),
        "observe-only alert must not dispatch toast notification"
    );

    // 3. Second outbound connect BEFORE MOTW resolves hits fast-path observe dedup and marks PID steady.
    sender
        .send(SensorEvent::NetworkConnect {
            pid: ident.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 72)),
            dst_port: 443,
            domain_hint: Some("obs2.example.invalid".to_string()),
            timestamp_ms: t0_ms + 200,
        })
        .await
        .expect("send second observe NetworkConnect");
    wait_high_priority_processed(&engine, 3, "second observe NetworkConnect").await;
    assert_eq!(
        store.list_alerts(None, 10).expect("list alerts after 2nd connect").len(),
        1,
        "duplicate observe-only connect must be suppressed by NET_OUTBOUND_OBSERVE"
    );

    // Confirm third pre-MOTW connect is now classified onto the Telemetry lane as steady.
    sender
        .send(SensorEvent::NetworkConnect {
            pid: ident.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 73)),
            dst_port: 443,
            domain_hint: Some("obs3.example.invalid".to_string()),
            timestamp_ms: t0_ms + 300,
        })
        .await
        .expect("send steady pre-MOTW NetworkConnect");
    let telem_deadline = Instant::now() + Duration::from_secs(2);
    while engine.metrics().telemetry_processed < 1 {
        assert!(
            Instant::now() < telem_deadline,
            "timed out waiting for steady pre-MOTW connect on telemetry lane"
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }

    // 4. Release the MOTW gate: delayed MOTW attribution backfills SQLite, clears steady PID
    //    classification, and installs the L-18 pre-emptive WFP block.
    {
        let (lock, cvar) = &*released;
        let mut flag = lock.lock().expect("lock released");
        *flag = true;
        cvar.notify_all();
    }

    let motw_deadline = Instant::now() + Duration::from_secs(2);
    let wfp_handle = loop {
        let _ = store.flush_batch();
        let snap = store
            .query_flight_recorder(10, Some(&ident.instance_id()))
            .expect("query process");
        let origin_ready = snap
            .processes
            .first()
            .and_then(|p| p.origin_url.as_deref())
            == Some("https://late-escalate.example.invalid/portable.exe");
        let block_handle = defense
            .added_wfp()
            .into_iter()
            .find(|c| !c.allow && c.exe_path.eq_ignore_ascii_case(exe_path))
            .map(|c| c.handle);
        if origin_ready {
            if let Some(handle) = block_handle {
                break handle;
            }
        }
        assert!(
            Instant::now() < motw_deadline,
            "timed out waiting for delayed MOTW backfill and L-18 WFP block"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    };

    // 5. First WFP drop after MOTW elevation must suspend the process, emit the enforced alert,
    //    and dispatch toast notification (NOT suppressed by prior NET_OUTBOUND_OBSERVE).
    assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
        os_filter_id: wfp_handle,
        rule_handle: wfp_handle,
        exe_path: exe_path.to_string(),
        protocol: 6,
        dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77)),
        dst_port: 443,
        timestamp_ms: t0_ms + 500,
        package_sid: None,
    }));

    let enforce_deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if defense.suspends().len() == 1
            && notifier.alerts().len() == 1
            && store.list_alerts(None, 10).expect("list alerts").len() == 2
        {
            break;
        }
        assert!(
            Instant::now() < enforce_deadline,
            "timed out waiting for enforced suspension, toast, and alert after MOTW elevation"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let alerts_after_first_drop = store.list_alerts(None, 10).expect("list alerts");
    let enforced_alert = alerts_after_first_drop
        .iter()
        .find(|a| a.process_suspended)
        .expect("enforced alert must be recorded with process_suspended=true");
    assert_eq!(enforced_alert.rule_id, "LEDR-NET-HIGH-RISK-PATH");
    let enforced_ctx: serde_json::Value =
        serde_json::from_str(&enforced_alert.context_json).expect("enforced alert context_json");
    assert_eq!(
        enforced_ctx.get("wfp_blocked").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        enforced_ctx.get("origin_url").and_then(|v| v.as_str()),
        Some("https://late-escalate.example.invalid/portable.exe")
    );
    assert_eq!(notifier.alerts()[0].alert_id, enforced_alert.alert_id);

    // 6. Verify `apply_late_motw_attribution` cleared steady-PID classification so a subsequent
    //    classified NetworkConnect re-enters the HighPriority lane (not Telemetry), while still
    //    being deduplicated by `NET_OUTBOUND`.
    sender
        .send(SensorEvent::NetworkConnect {
            pid: ident.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 78)),
            dst_port: 443,
            domain_hint: Some("post-motw.example.invalid".to_string()),
            timestamp_ms: t0_ms + 1_200,
        })
        .await
        .expect("send post-MOTW NetworkConnect");
    wait_high_priority_processed(&engine, 4, "post-MOTW NetworkConnect on high-priority lane")
        .await;
    assert_eq!(
        engine.metrics().telemetry_processed,
        1,
        "post-MOTW connect must route to HighPriority lane after remove_pid(pid)"
    );

    // 7. Second WFP drop past the 250 ms WfpDropDedupCache window must be suppressed by
    //    `NET_OUTBOUND` so suspend, toast, and enforced alert each happen exactly once.
    assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
        os_filter_id: wfp_handle,
        rule_handle: wfp_handle,
        exe_path: exe_path.to_string(),
        protocol: 6,
        dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 79)),
        dst_port: 8443,
        timestamp_ms: t0_ms + 1_500,
        package_sid: None,
    }));

    // Shutdown drains every remaining queued WFP drop deterministically without cross-lane barriers.
    engine.shutdown_and_flush().await.expect("shutdown");

    assert_eq!(
        defense.suspends(),
        vec![ident],
        "process must be suspended exactly once"
    );
    assert_eq!(
        notifier.alerts().len(),
        1,
        "toast notification must be dispatched exactly once"
    );
    assert_eq!(
        store.list_alerts(None, 20).expect("final alerts").len(),
        2,
        "expected exactly 1 observe alert + 1 enforced alert (second drop suppressed)"
    );
}

#[tokio::test]
async fn daemon_p4_20_seed_processes_deduplicates_motw_groups_beyond_realtime_queue_cap_without_persistence_race()
{
    let motw = Arc::new(MapMotwInspector::default());
    let distinct_motw_exes = 70usize; // Strictly exceeds MOTW_IO_QUEUE_CAPACITY (64)
    let duplicate_instances = 50usize; // Extra instances sharing case-preserving normalized path variants (total 120 MOTW procs)
    let protected_os_instances = 10usize;

    let mut expected_origins: HashMap<String, String> = HashMap::new();
    let mut snapshots: Vec<SensorEvent> =
        Vec::with_capacity(distinct_motw_exes + duplicate_instances + protected_os_instances);
    let base_ms = 1_760_020_000_000i64;
    let mut next_pid = 20_000u32;

    for i in 0..distinct_motw_exes {
        let canonical_exe = format!(r"C:\Apps\SeedTool{i:02}\tool{i:02}.exe");
        let origin_url = format!("https://seed-origin.example.invalid/tool{i:02}.exe");
        motw.insert(
            &canonical_exe,
            MotwZoneInfo {
                zone_id: 3,
                host_url: Some(origin_url.clone()),
                referrer_url: Some("https://seed-ref.example.invalid/".to_string()),
            },
        );
        let ident = ProcessIdentity::new(next_pid, unix_ms_to_filetime(base_ms + i as i64));
        next_pid += 1;
        expected_origins.insert(ident.instance_id(), origin_url);
        snapshots.push(SensorEvent::ProcessStart {
            identity: ident,
            parent_pid: 4,
            exe_path: canonical_exe,
            command_line: format!("tool{i:02}.exe --primary"),
            user_sid: None,
        });
    }

    for i in 0..duplicate_instances {
        let variant_exe = match i % 3 {
            0 => format!("C:/Apps/SeedTool{i:02}/tool{i:02}.exe"),
            1 => format!(r"\\?\C:\Apps\SeedTool{i:02}\tool{i:02}.exe"),
            _ => format!("//?/C:/Apps/SeedTool{i:02}/tool{i:02}.exe"),
        };
        let origin_url = format!("https://seed-origin.example.invalid/tool{i:02}.exe");
        let ident = ProcessIdentity::new(
            next_pid,
            unix_ms_to_filetime(base_ms + 1_000 + i as i64),
        );
        next_pid += 1;
        expected_origins.insert(ident.instance_id(), origin_url);
        snapshots.push(SensorEvent::ProcessStart {
            identity: ident,
            parent_pid: 4,
            exe_path: variant_exe,
            command_line: format!("tool{i:02}.exe --worker"),
            user_sid: None,
        });
    }

    let mut protected_ids: Vec<String> = Vec::with_capacity(protected_os_instances);
    for i in 0..protected_os_instances {
        let ident = ProcessIdentity::new(
            next_pid,
            unix_ms_to_filetime(base_ms + 2_000 + i as i64),
        );
        next_pid += 1;
        protected_ids.push(ident.instance_id());
        snapshots.push(SensorEvent::ProcessStart {
            identity: ident,
            parent_pid: 4,
            exe_path: r"C:\Windows\System32\svchost.exe".to_string(),
            command_line: format!("svchost.exe -k netsvcs -i {i}"),
            user_sid: None,
        });
    }

    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockDefense::new());
    let engine = DaemonEngine::start_with_motw_inspector(
        store.clone(),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::PreemptiveOnly,
            ..DaemonConfig::default()
        },
        defense.clone(),
        Arc::new(RecordingNotifier::default()),
        Arc::new(MapBinaryInspector::default()),
        Arc::new(NullLiveProcessInspector),
        motw.clone(),
    );

    let total_seeded = engine.seed_processes(snapshots).expect("seed_processes");
    assert_eq!(
        total_seeded,
        distinct_motw_exes + duplicate_instances + protected_os_instances
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let snap = store.query_flight_recorder(256, None).expect("query store");
        let matched_count = snap
            .processes
            .iter()
            .filter(|p| {
                expected_origins
                    .get(&p.process_instance_id)
                    .is_some_and(|exp| p.origin_url.as_deref() == Some(exp.as_str()))
            })
            .count();
        let wfp_blocks = defense.added_wfp().iter().filter(|c| !c.allow).count();
        if matched_count == expected_origins.len() && wfp_blocks == distinct_motw_exes {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for seed MOTW backfill: matched={matched_count}/{}, wfp_blocks={wfp_blocks}/{distinct_motw_exes}",
            expected_origins.len()
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // Deduplication by case-preserving normalized path must reduce MOTW I/O from 120 down to 70
    // (and skip all 10 ProtectedOs `svchost.exe` processes).
    assert_eq!(
        motw.calls().len(),
        distinct_motw_exes,
        "expected exactly one MOTW lookup per deduplicated non-ProtectedOs executable group"
    );

    let final_snap = store.query_flight_recorder(256, None).expect("query final store");
    assert_eq!(final_snap.processes.len(), total_seeded);
    for proc_row in &final_snap.processes {
        if let Some(expected_url) = expected_origins.get(&proc_row.process_instance_id) {
            assert_eq!(
                proc_row.origin_url.as_deref(),
                Some(expected_url.as_str()),
                "seeded process {} missing expected MOTW origin_url in SQLite",
                proc_row.process_instance_id
            );
        } else {
            assert!(protected_ids.contains(&proc_row.process_instance_id));
            assert_eq!(proc_row.origin_url, None);
        }
    }

    let added_wfp = defense.added_wfp();
    assert_eq!(added_wfp.len(), distinct_motw_exes);
    assert!(
        added_wfp
            .iter()
            .all(|c| !c.allow && !c.exe_path.to_ascii_lowercase().ends_with("svchost.exe")),
        "only the 70 distinct MOTW executables must receive L-18 pre-emptive WFP blocks"
    );

    engine.shutdown_and_flush().await.expect("shutdown");
}

#[tokio::test]
async fn daemon_p4_21_stage2_same_size_mtime_replacement_partial_purge_invalidation_and_default_cancellable_sha256()
{
    let dir = TestTempDir::new("p4-21");

    // --- Part A: Same-size, same-mtime binary replacement must NOT reuse stale Stage 2 SHA-256 / URL ---
    let orig_dl_path = dir.0.join("dl_orig_a.exe");
    let moved_path = dir.0.join("moved_tool.exe");
    let payload_a = b"download-payload-AAAA-1234567890";
    let payload_clean_same_len = b"clean-build-BBBB-0987654321-xxxx";
    assert_eq!(payload_a.len(), payload_clean_same_len.len());
    std::fs::write(&orig_dl_path, payload_a).expect("write dl_orig_a");
    std::fs::write(&moved_path, payload_a).expect("write moved_tool");
    let expected_sha_a = compute_file_sha256_hex(&orig_dl_path).expect("hash payload_a");

    let orig_meta = std::fs::metadata(&moved_path).expect("stat moved_tool");
    let orig_len = orig_meta.len();
    let orig_mtime = orig_meta.modified().expect("read orig mtime");

    let store = LedrStore::open_in_memory().expect("open store");
    let engine = DaemonEngine::start_with_motw_inspector(
        store.clone(),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        Arc::new(MockDefense::new()),
        Arc::new(RecordingNotifier::default()),
        Arc::new(WindowsBinaryInspector::new()),
        Arc::new(NullLiveProcessInspector),
        Arc::new(WindowsMotwInspector::new()),
    );

    let now_ms = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_millis(),
    )
    .expect("i64 ms");
    let expired_ts = now_ms - 40 * 86_400_000;

    engine
        .record_browser_download_origin(
            &orig_dl_path.display().to_string(),
            "https://orig-a.example.invalid/a.exe",
            None,
            None,
            expired_ts,
        )
        .expect("record expired download A");

    let moved_str = moved_path.display().to_string();
    let first_a = engine
        .resolve_process_motw(&moved_str, None, false)
        .expect("Stage 2 match for payload_a");
    assert_eq!(first_a.stage, MotwMatchStage::DownloadSha256);
    assert_eq!(first_a.origin_url, "https://orig-a.example.invalid/a.exe");
    assert_eq!(first_a.sha256.as_deref(), Some(expected_sha_a.as_str()));

    let hits_before = engine.motw_stage2_cache_hits();
    let second_a = engine
        .resolve_process_motw(&moved_str, None, false)
        .expect("Stage 2 cache hit for payload_a");
    assert_eq!(second_a.origin_url, "https://orig-a.example.invalid/a.exe");
    assert_eq!(engine.motw_stage2_cache_hits(), hits_before + 1);

    // Replace `moved_tool.exe` with different bytes of the EXACT same length and restore `orig_mtime`.
    std::fs::write(&moved_path, payload_clean_same_len).expect("overwrite moved_tool");
    std::fs::OpenOptions::new()
        .write(true)
        .open(&moved_path)
        .expect("open moved_tool for set_modified")
        .set_modified(orig_mtime)
        .expect("restore original mtime");
    let replaced_meta = std::fs::metadata(&moved_path).expect("stat replaced moved_tool");
    assert_eq!(replaced_meta.len(), orig_len);
    assert_eq!(
        replaced_meta.modified().expect("read replaced mtime"),
        orig_mtime
    );

    assert_eq!(
        engine.resolve_process_motw(&moved_str, None, false),
        None,
        "same-size, same-mtime replacement must compute fresh SHA-256 and never reuse stale Stage 2 URL/hash"
    );

    // --- Part B: Partial TTL purge (expired A + valid B) immediately invalidates A's Stage 2 cache
    //     while preserving `has_download_origins_cached() == true` and continuing to resolve B ---
    let moved_a_path = dir.0.join("moved_expired_a.exe");
    let orig_dl_b_path = dir.0.join("dl_valid_b.exe");
    let moved_b_path = dir.0.join("moved_valid_b.exe");
    let payload_b = b"valid-recent-download-payload-BBBB-99999";
    std::fs::write(&moved_a_path, payload_a).expect("write moved_expired_a");
    std::fs::write(&orig_dl_b_path, payload_b).expect("write dl_valid_b");
    std::fs::write(&moved_b_path, payload_b).expect("write moved_valid_b");
    let expected_sha_b = compute_file_sha256_hex(&orig_dl_b_path).expect("hash payload_b");

    engine
        .record_browser_download_origin(
            &orig_dl_b_path.display().to_string(),
            "https://valid-b.example.invalid/b.exe",
            None,
            None,
            now_ms,
        )
        .expect("record valid download B");

    let moved_a_str = moved_a_path.display().to_string();
    let moved_b_str = moved_b_path.display().to_string();
    // Warm Stage 2 cache for both A and B under the current generation.
    assert_eq!(
        engine
            .resolve_process_motw(&moved_a_str, None, false)
            .map(|m| m.origin_url),
        Some("https://orig-a.example.invalid/a.exe".to_string())
    );
    assert_eq!(
        engine
            .resolve_process_motw(&moved_b_str, None, false)
            .map(|m| m.origin_url),
        Some("https://valid-b.example.invalid/b.exe".to_string())
    );
    let hits_pre_purge = engine.motw_stage2_cache_hits();
    assert!(engine.resolve_process_motw(&moved_a_str, None, false).is_some());
    assert!(engine.resolve_process_motw(&moved_b_str, None, false).is_some());
    assert_eq!(engine.motw_stage2_cache_hits(), hits_pre_purge + 2);

    // Purge expired A while valid B remains.
    let purge_stats = engine.run_ttl_purge_once().expect("run partial TTL purge");
    assert_eq!(purge_stats.downloads_deleted, 1);
    assert!(
        engine.has_download_origins_cached(),
        "has_download_origins_cached must remain true while valid download B still exists"
    );

    let hits_post_purge = engine.motw_stage2_cache_hits();
    assert_eq!(
        engine.resolve_process_motw(&moved_a_str, None, false),
        None,
        "expired download A's Stage 2 cache entry must be invalidated immediately after partial purge"
    );
    let resolved_b = engine
        .resolve_process_motw(&moved_b_str, None, false)
        .expect("valid download B must continue resolving after partial purge");
    assert_eq!(resolved_b.stage, MotwMatchStage::DownloadSha256);
    assert_eq!(resolved_b.origin_url, "https://valid-b.example.invalid/b.exe");
    assert_eq!(resolved_b.sha256.as_deref(), Some(expected_sha_b.as_str()));
    assert_eq!(
        engine.motw_stage2_cache_hits(),
        hits_post_purge,
        "first post-purge lookups must miss old generation before repopulating new generation"
    );
    assert!(engine.resolve_process_motw(&moved_b_str, None, false).is_some());
    assert_eq!(engine.motw_stage2_cache_hits(), hits_post_purge + 1);

    engine.shutdown_and_flush().await.expect("shutdown engine");

    // Verify periodic `pipeline.rs` TTL purge also advances generation when rows remain.
    let periodic_engine = DaemonEngine::start_with_motw_inspector(
        LedrStore::open_in_memory().expect("open periodic store"),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ttl_purge_interval_ms: 50,
            ..DaemonConfig::default()
        },
        Arc::new(MockDefense::new()),
        Arc::new(RecordingNotifier::default()),
        Arc::new(WindowsBinaryInspector::new()),
        Arc::new(NullLiveProcessInspector),
        Arc::new(WindowsMotwInspector::new()),
    );
    periodic_engine
        .record_browser_download_origin(
            &orig_dl_path.display().to_string(),
            "https://periodic-expired.example.invalid/a.exe",
            None,
            None,
            expired_ts,
        )
        .expect("record periodic expired A");
    periodic_engine
        .record_browser_download_origin(
            &orig_dl_b_path.display().to_string(),
            "https://periodic-valid.example.invalid/b.exe",
            None,
            None,
            now_ms,
        )
        .expect("record periodic valid B");
    assert!(periodic_engine
        .resolve_process_motw(&moved_a_str, None, false)
        .is_some());
    let periodic_deadline = Instant::now() + Duration::from_secs(2);
    while periodic_engine
        .resolve_process_motw(&moved_a_str, None, false)
        .is_some()
    {
        assert!(
            Instant::now() < periodic_deadline,
            "periodic pipeline TTL purge failed to invalidate expired Stage 2 cache entry"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(periodic_engine.has_download_origins_cached());
    assert_eq!(
        periodic_engine
            .resolve_process_motw(&moved_b_str, None, false)
            .map(|m| m.origin_url),
        Some("https://periodic-valid.example.invalid/b.exe".to_string())
    );
    periodic_engine
        .shutdown_and_flush()
        .await
        .expect("shutdown periodic engine");

    // --- Part C: Default `BinaryInspector::compute_sha256_cancellable` size cap & cancel contract ---
    struct DefaultCancellableMock {
        inspect_calls: AtomicU64,
        cancel_during_inspect: Option<Arc<AtomicBool>>,
    }

    impl BinaryInspector for DefaultCancellableMock {
        fn inspect(&self, exe_path: &str) -> BinaryIdentity {
            self.inspect_calls.fetch_add(1, Ordering::AcqRel);
            if let Some(flag) = &self.cancel_during_inspect {
                flag.store(true, Ordering::Release);
            }
            BinaryIdentity {
                exe_path: exe_path.to_string(),
                sha256: Some(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                ),
                authenticode: None,
            }
        }
    }

    let sized_file = dir.0.join("default_cap_probe.bin");
    std::fs::write(&sized_file, vec![b'Z'; 64]).expect("write 64-byte probe file");
    let sized_str = sized_file.display().to_string();

    let mock_insp = DefaultCancellableMock {
        inspect_calls: AtomicU64::new(0),
        cancel_during_inspect: None,
    };
    let cancel_false = AtomicBool::new(false);

    // Real file > max_bytes returns Ok(None) without invoking `inspect()`.
    assert_eq!(
        mock_insp
            .compute_sha256_cancellable(&sized_str, 16, &cancel_false)
            .expect("oversized default check"),
        None
    );
    assert_eq!(mock_insp.inspect_calls.load(Ordering::Acquire), 0);

    // Real file <= max_bytes delegates to `compute_sha256()`.
    assert!(mock_insp
        .compute_sha256_cancellable(&sized_str, 64, &cancel_false)
        .expect("within limit")
        .is_some());
    assert_eq!(mock_insp.inspect_calls.load(Ordering::Acquire), 1);

    // Non-existent path (`ErrorKind::NotFound`) passes through for in-memory mocks.
    assert!(mock_insp
        .compute_sha256_cancellable(r"C:\NonExistent\mock_only.exe", 16, &cancel_false)
        .expect("NotFound mock passthrough")
        .is_some());
    assert_eq!(mock_insp.inspect_calls.load(Ordering::Acquire), 2);

    // Pre-cancelled token returns Err(Interrupted) without calling `inspect()`.
    let cancel_true = AtomicBool::new(true);
    let pre_err = mock_insp
        .compute_sha256_cancellable(&sized_str, 64, &cancel_true)
        .expect_err("pre-cancelled must fail");
    assert_eq!(pre_err.kind(), ErrorKind::Interrupted);
    assert_eq!(mock_insp.inspect_calls.load(Ordering::Acquire), 2);

    // Mid-call cancellation is caught by the post-execution recheck.
    let cancel_mid = Arc::new(AtomicBool::new(false));
    let mid_mock = DefaultCancellableMock {
        inspect_calls: AtomicU64::new(0),
        cancel_during_inspect: Some(Arc::clone(&cancel_mid)),
    };
    let post_err = mid_mock
        .compute_sha256_cancellable(&sized_str, 64, &cancel_mid)
        .expect_err("post-call cancel recheck must fail");
    assert_eq!(post_err.kind(), ErrorKind::Interrupted);
    assert_eq!(mid_mock.inspect_calls.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn daemon_p4_22_seed_case_sensitivity_and_nonblocking_late_motw_fair_drain() {
    // --- Part A (`PRRT_kwDOVyjVyM66QCZw`): Case-preserving seed MOTW grouping separates
    //     distinct case-sensitive NTFS executables (`Tool.exe` vs `tool.exe`). ---
    struct CaseSensitiveMotwInspector {
        zones: Mutex<HashMap<String, MotwZoneInfo>>,
        calls: Mutex<Vec<String>>,
        call_count: Arc<(Mutex<usize>, Condvar)>,
    }

    impl CaseSensitiveMotwInspector {
        fn new() -> Self {
            Self {
                zones: Mutex::new(HashMap::new()),
                calls: Mutex::new(Vec::new()),
                call_count: Arc::new((Mutex::new(0usize), Condvar::new())),
            }
        }

        fn insert_exact(&self, path: &str, zone: MotwZoneInfo) {
            self.zones
                .lock()
                .expect("lock case-sensitive zones")
                .insert(path.replace('/', "\\"), zone);
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().expect("lock case-sensitive calls").clone()
        }
    }

    impl MotwInspector for CaseSensitiveMotwInspector {
        fn read_zone_identifier(&self, path: &Path) -> Option<MotwZoneInfo> {
            let raw = path.display().to_string();
            let normalized = raw.replace('/', "\\");
            self.calls
                .lock()
                .expect("lock case-sensitive calls")
                .push(normalized.clone());
            let result = self
                .zones
                .lock()
                .expect("lock case-sensitive zones")
                .get(&normalized)
                .cloned();
            let (lock, cvar) = &*self.call_count;
            let mut count = lock.lock().expect("lock call_count");
            *count += 1;
            cvar.notify_all();
            result
        }
    }

    let case_motw = Arc::new(CaseSensitiveMotwInspector::new());
    let upper_exe = r"C:\CaseApps\Tool.exe";
    let lower_exe = r"C:\CaseApps\tool.exe";
    case_motw.insert_exact(
        upper_exe,
        MotwZoneInfo {
            zone_id: 3,
            host_url: Some("https://case-upper.example.invalid/Tool.exe".to_string()),
            referrer_url: Some("https://case-ref.example.invalid/".to_string()),
        },
    );

    let store_a = LedrStore::open_in_memory().expect("open store A");
    let engine_a = DaemonEngine::start_with_motw_inspector(
        store_a.clone(),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        Arc::new(MockDefense::new()),
        Arc::new(RecordingNotifier::default()),
        Arc::new(MapBinaryInspector::default()),
        Arc::new(NullLiveProcessInspector),
        case_motw.clone(),
    );

    let base_a_ms = 1_760_022_000_000i64;
    let upper_ident = ProcessIdentity::new(22_001, unix_ms_to_filetime(base_a_ms));
    let lower_ident = ProcessIdentity::new(22_002, unix_ms_to_filetime(base_a_ms + 10));
    let seeded_a = engine_a
        .seed_processes(vec![
            SensorEvent::ProcessStart {
                identity: upper_ident,
                parent_pid: 4,
                exe_path: upper_exe.to_string(),
                command_line: "Tool.exe".to_string(),
                user_sid: None,
            },
            SensorEvent::ProcessStart {
                identity: lower_ident,
                parent_pid: 4,
                exe_path: lower_exe.to_string(),
                command_line: "tool.exe".to_string(),
                user_sid: None,
            },
        ])
        .expect("seed_processes Part A");
    assert_eq!(seeded_a, 2);

    let call_count_wait = Arc::clone(&case_motw.call_count);
    tokio::task::spawn_blocking(move || wait_count_reached(&call_count_wait, 2))
        .await
        .expect("wait both case-sensitive MOTW lookups");

    let upper_deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let snap = store_a
            .query_flight_recorder(10, Some(&upper_ident.instance_id()))
            .expect("query upper Tool.exe");
        if snap
            .processes
            .first()
            .and_then(|p| p.origin_url.as_deref())
            == Some("https://case-upper.example.invalid/Tool.exe")
        {
            break;
        }
        assert!(
            Instant::now() < upper_deadline,
            "timed out waiting for Tool.exe seed MOTW origin_url"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    engine_a
        .shutdown_and_flush()
        .await
        .expect("shutdown Part A engine");

    let case_calls = case_motw.calls();
    assert_eq!(
        case_calls.len(),
        2,
        "Tool.exe and tool.exe must be resolved separately (calls={case_calls:?})"
    );
    assert!(case_calls.iter().any(|p| p == upper_exe));
    assert!(case_calls.iter().any(|p| p == lower_exe));

    let upper_final = store_a
        .query_flight_recorder(10, Some(&upper_ident.instance_id()))
        .expect("query final upper Tool.exe");
    assert_eq!(
        upper_final.processes[0].origin_url.as_deref(),
        Some("https://case-upper.example.invalid/Tool.exe")
    );
    let lower_final = store_a
        .query_flight_recorder(10, Some(&lower_ident.instance_id()))
        .expect("query final lower tool.exe");
    assert_eq!(
        lower_final.processes[0].origin_url, None,
        "tool.exe must not inherit Tool.exe's MOTW origin_url"
    );
    assert_eq!(
        lower_final.processes[0].sha256, None,
        "tool.exe must not inherit Tool.exe's SHA-256"
    );

    // --- Part B (`PRRT_kwDOVyjVyM66QCaz`, A-1): Saturated `motw_result_tx` (64) + 80 MOTW seed
    //     groups + 200 HighPriority burst never starves IPC `ReportDownloadOrigin` (with real
    //     file SHA-256), advances seeds during Tier 1 bursts via 16-event fair interleave,
    //     completes all 80 seed groups with 0 drops, and shuts down within budget. ---
    struct BurstGateMotwInspector {
        zones: HashMap<String, MotwZoneInfo>,
        seed_calls: Arc<(Mutex<usize>, Condvar)>,
        gate1_entered: Arc<(Mutex<usize>, Condvar)>,
        gate1_released: Arc<(Mutex<bool>, Condvar)>,
        gate2_entered: Arc<(Mutex<usize>, Condvar)>,
        gate2_released: Arc<(Mutex<bool>, Condvar)>,
    }

    impl MotwInspector for BurstGateMotwInspector {
        fn read_zone_identifier(&self, path: &Path) -> Option<MotwZoneInfo> {
            let raw = path.display().to_string();
            if raw.ends_with("gate1_holder.exe") {
                {
                    let (lock, cvar) = &*self.gate1_entered;
                    let mut count = lock.lock().expect("lock gate1_entered");
                    *count += 1;
                    cvar.notify_all();
                }
                {
                    let (lock, cvar) = &*self.gate1_released;
                    let mut flag = lock.lock().expect("lock gate1_released");
                    while !*flag {
                        flag = cvar.wait(flag).expect("wait gate1_released");
                    }
                }
                return None;
            }
            if raw.ends_with("gate2_midburst.exe") {
                {
                    let (lock, cvar) = &*self.gate2_entered;
                    let mut count = lock.lock().expect("lock gate2_entered");
                    *count += 1;
                    cvar.notify_all();
                }
                {
                    let (lock, cvar) = &*self.gate2_released;
                    let mut flag = lock.lock().expect("lock gate2_released");
                    while !*flag {
                        flag = cvar.wait(flag).expect("wait gate2_released");
                    }
                }
                return None;
            }
            let normalized = raw.replace('/', "\\");
            let found = self.zones.get(&normalized).cloned();
            if normalized.contains(r"\seed_") {
                let (lock, cvar) = &*self.seed_calls;
                let mut count = lock.lock().expect("lock seed_calls");
                *count += 1;
                cvar.notify_all();
            }
            found
        }
    }

    let seed_group_count = 80usize; // Strictly exceeds MOTW_IO_QUEUE_CAPACITY (64)
    let burst_hp_count = 200u32;
    let base_b_ms = 1_760_022_100_000i64;

    let mut seed_zones: HashMap<String, MotwZoneInfo> = HashMap::with_capacity(seed_group_count);
    let mut expected_seed_origins: HashMap<String, String> =
        HashMap::with_capacity(seed_group_count);
    let mut seed_snapshots: Vec<SensorEvent> = Vec::with_capacity(seed_group_count);
    for i in 0..seed_group_count {
        let exe = format!(r"C:\SeedBurst\seed_{i:02}.exe");
        let url = format!("https://seed-burst.example.invalid/seed_{i:02}.exe");
        seed_zones.insert(
            exe.clone(),
            MotwZoneInfo {
                zone_id: 3,
                host_url: Some(url.clone()),
                referrer_url: Some("https://seed-burst-ref.example.invalid/".to_string()),
            },
        );
        let ident = ProcessIdentity::new(
            32_000 + i as u32,
            unix_ms_to_filetime(base_b_ms + 10_000 + i as i64),
        );
        expected_seed_origins.insert(ident.instance_id(), url);
        seed_snapshots.push(SensorEvent::ProcessStart {
            identity: ident,
            parent_pid: 4,
            exe_path: exe,
            command_line: format!("seed_{i:02}.exe"),
            user_sid: None,
        });
    }

    let dir_b = TestTempDir::new("p4-22");
    let dl_file = dir_b.0.join("urgent_download.exe");
    std::fs::write(&dl_file, b"p4-22-urgent-download-payload-for-sha256")
        .expect("write urgent_download.exe");
    let expected_dl_sha = compute_file_sha256_hex(&dl_file).expect("hash urgent_download.exe");
    let dl_path_str = dl_file.display().to_string();

    let seed_calls = Arc::new((Mutex::new(0usize), Condvar::new()));
    let gate1_entered = Arc::new((Mutex::new(0usize), Condvar::new()));
    let gate1_released = Arc::new((Mutex::new(false), Condvar::new()));
    let gate2_entered = Arc::new((Mutex::new(0usize), Condvar::new()));
    let gate2_released = Arc::new((Mutex::new(false), Condvar::new()));
    let _gate1_guard = GateReleaseGuard(Arc::clone(&gate1_released));
    let _gate2_guard = GateReleaseGuard(Arc::clone(&gate2_released));

    let burst_motw = Arc::new(BurstGateMotwInspector {
        zones: seed_zones,
        seed_calls: Arc::clone(&seed_calls),
        gate1_entered: Arc::clone(&gate1_entered),
        gate1_released: Arc::clone(&gate1_released),
        gate2_entered: Arc::clone(&gate2_entered),
        gate2_released: Arc::clone(&gate2_released),
    });

    let pipe_b = unique_test_pipe_name();
    let store_b = LedrStore::open_in_memory().expect("open store B");
    let engine_b = DaemonEngine::start_with_motw_inspector(
        store_b.clone(),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: pipe_b.clone(),
            dev_mode_bypass_ui_auth: true,
            ipc_session_timeout_ms: 1_500,
            motw_sync_wait_budget_ms: 5_000,
            shutdown_flush_timeout_ms: 3_000,
            ..DaemonConfig::default()
        },
        Arc::new(MockDefense::new()),
        Arc::new(RecordingNotifier::default()),
        Arc::new(WindowsBinaryInspector::new()),
        Arc::new(NullLiveProcessInspector),
        burst_motw,
    );
    let ipc_b = start_ipc_server(Arc::clone(&engine_b)).expect("bind Part B IPC pipe");
    let sender_b = engine_b.sender();

    // 1. Park `run_pipeline` and worker 0 on `gate1_holder.exe` so `motw_result_rx` cannot drain
    //    while worker 1 saturates `motw_result_tx` (capacity 64) with startup seed results.
    sender_b
        .send(SensorEvent::ProcessStart {
            identity: ProcessIdentity::new(30_000, unix_ms_to_filetime(base_b_ms)),
            parent_pid: 4,
            exe_path: r"C:\SeedBurst\gate1_holder.exe".to_string(),
            command_line: "gate1_holder.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send gate1_holder ProcessStart");
    let gate1_wait = Arc::clone(&gate1_entered);
    tokio::task::spawn_blocking(move || wait_count_reached(&gate1_wait, 1))
        .await
        .expect("wait gate1_holder in MOTW worker");

    // 2. Preload a 200-event HighPriority burst behind `gate1_holder`, placing `gate2_midburst`
    //    at index 40 (> 2 * 16 interleave cycles, with 159 HP events still queued behind it).
    for i in 0..burst_hp_count {
        let exe_path = if i == 40 {
            r"C:\SeedBurst\gate2_midburst.exe".to_string()
        } else {
            r"C:\Windows\System32\svchost.exe".to_string()
        };
        sender_b
            .send(SensorEvent::ProcessStart {
                identity: ProcessIdentity::new(
                    31_000 + i,
                    unix_ms_to_filetime(base_b_ms + 1_000 + i64::from(i)),
                ),
                parent_pid: 4,
                exe_path,
                command_line: format!("hp_burst_{i}"),
                user_sid: None,
            })
            .await
            .expect("preload HighPriority burst event");
    }

    // 3. Seed 80 distinct MOTW groups and deterministically wait until worker 1 has filled all 64
    //    slots of `motw_result_tx` and paused at the `w_late_tx.capacity() > 0` gate.
    let seeded_b = engine_b
        .seed_processes(seed_snapshots)
        .expect("seed 80 MOTW groups");
    assert_eq!(seeded_b, seed_group_count);

    let seed_wait_64 = Arc::clone(&seed_calls);
    tokio::task::spawn_blocking(move || wait_count_reached(&seed_wait_64, 64))
        .await
        .expect("wait worker 1 to saturate motw_result_tx (64)");

    // 4. While `gate1` is STILL closed (`motw_result_tx` 64/64 full, worker 0 held, 200 HP events
    //    queued), send IPC `ReportDownloadOrigin` with real SHA-256 computation. Worker 1 must
    //    preempt deferred seed work and reply `Ack` promptly instead of deadlocking.
    let dl_t0 = Instant::now();
    let pipe_for_dl = pipe_b.clone();
    let dl_path_req = dl_path_str.clone();
    let dl_resp = tokio::task::spawn_blocking(move || {
        send_pipe_request(
            &pipe_for_dl,
            &IpcRequest::ReportDownloadOrigin {
                file_path: dl_path_req,
                tab_url: "https://urgent-dl.example.invalid/urgent_download.exe".to_string(),
                frame_url: None,
                referrer_url: Some("https://urgent-ref.example.invalid/".to_string()),
                downloaded_at_ms: base_b_ms + 500,
            },
        )
    })
    .await
    .expect("join ReportDownloadOrigin client");
    let dl_elapsed = dl_t0.elapsed();
    assert!(
        matches!(dl_resp, IpcResponse::Ack { .. }),
        "IPC ReportDownloadOrigin must return Ack while motw_result_tx is full: {dl_resp:?}"
    );
    assert!(
        dl_elapsed < Duration::from_secs(1),
        "IPC ReportDownloadOrigin took {dl_elapsed:?} under saturated motw_result_tx"
    );
    assert_eq!(
        *seed_calls.0.lock().expect("lock seed_calls after dl"),
        64,
        "w_late_tx.capacity() > 0 gate must prevent popping the 65th seed while motw_result_tx is full"
    );

    let dl_snap = store_b
        .query_flight_recorder(10, None)
        .expect("query persisted download_origins");
    assert_eq!(dl_snap.download_origins.len(), 1);
    assert_eq!(
        dl_snap.download_origins[0].sha256.as_deref(),
        Some(expected_dl_sha.as_str()),
        "IPC ReportDownloadOrigin must persist computed real-file SHA-256"
    );
    assert_eq!(
        dl_snap.download_origins[0].tab_url,
        "https://urgent-dl.example.invalid/urgent_download.exe"
    );

    // 5. Release `gate1`: Tier 1 processes 40 consecutive HP events before reaching `gate2`,
    //    triggering at least two 16-event Tier 1b interleaves so `seed_backlog` advances to at
    //    least the 66th group while 159 HP events remain queued in Tier 1.
    {
        let (lock, cvar) = &*gate1_released;
        let mut flag = lock.lock().expect("lock gate1_released");
        *flag = true;
        cvar.notify_all();
    }
    let gate2_wait = Arc::clone(&gate2_entered);
    tokio::task::spawn_blocking(move || wait_count_reached(&gate2_wait, 1))
        .await
        .expect("wait gate2_midburst after 40 Tier 1 events");
    let seed_wait_66 = Arc::clone(&seed_calls);
    tokio::task::spawn_blocking(move || wait_count_reached(&seed_wait_66, 66))
        .await
        .expect("Tier 1 fair interleave must drain motw_result_rx and advance seed_backlog mid-burst");

    // 6. Release `gate2`: confirm all 201 HP events and all 80 MOTW seed groups complete with
    //    zero drops and `shutdown_and_flush` finishes within budget.
    {
        let (lock, cvar) = &*gate2_released;
        let mut flag = lock.lock().expect("lock gate2_released");
        *flag = true;
        cvar.notify_all();
    }
    wait_high_priority_processed(
        &engine_b,
        1 + u64::from(burst_hp_count),
        "gate1 + 200 HighPriority burst",
    )
    .await;

    let seed_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let snap = store_b
            .query_flight_recorder(512, None)
            .expect("query store B seeds");
        let matched = snap
            .processes
            .iter()
            .filter(|p| {
                expected_seed_origins
                    .get(&p.process_instance_id)
                    .is_some_and(|exp| p.origin_url.as_deref() == Some(exp.as_str()))
            })
            .count();
        if matched == seed_group_count {
            break;
        }
        assert!(
            Instant::now() < seed_deadline,
            "timed out waiting for all {seed_group_count} MOTW seed groups (matched={matched})"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    assert_eq!(engine_b.high_priority_dropped(), 0);
    ipc_b.shutdown().await;
    let shutdown_t0 = Instant::now();
    engine_b
        .shutdown_and_flush()
        .await
        .expect("shutdown Part B engine cleanly within budget");
    assert!(
        shutdown_t0.elapsed() < Duration::from_secs(3),
        "shutdown_and_flush exceeded 3s budget: {:?}",
        shutdown_t0.elapsed()
    );

    let final_b = store_b
        .query_flight_recorder(512, None)
        .expect("query final store B");
    let final_matched = final_b
        .processes
        .iter()
        .filter(|p| {
            expected_seed_origins
                .get(&p.process_instance_id)
                .is_some_and(|exp| p.origin_url.as_deref() == Some(exp.as_str()))
        })
        .count();
    assert_eq!(
        final_matched, seed_group_count,
        "all 80 seed MOTW groups must persist origin_url with zero loss"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_p4_23_saturated_motw_burst_above_pending_late_zero_loss_and_ipc_responsive() {
    #[derive(Clone)]
    struct CanaryGate {
        entered: Arc<(Mutex<usize>, Condvar)>,
        released: Arc<(Mutex<bool>, Condvar)>,
    }

    impl CanaryGate {
        fn new() -> (Self, GateReleaseGuard) {
            let entered = Arc::new((Mutex::new(0usize), Condvar::new()));
            let released = Arc::new((Mutex::new(false), Condvar::new()));
            let guard = GateReleaseGuard(Arc::clone(&released));
            (Self { entered, released }, guard)
        }

        fn wait_inside(&self) {
            let do_wait = || {
                {
                    let (lock, cvar) = &*self.entered;
                    let mut count = lock.lock().expect("lock canary gate entered");
                    *count += 1;
                    cvar.notify_all();
                }
                {
                    let (lock, cvar) = &*self.released;
                    let mut flag = lock.lock().expect("lock canary gate released");
                    while !*flag {
                        flag = cvar.wait(flag).expect("wait canary gate released");
                    }
                }
            };
            // Yield the Tokio worker slot before blocking on a Condvar so the multi-threaded
            // runtime's timer driver and IPC server remain responsive while `run_pipeline` is paused.
            if tokio::runtime::Handle::try_current()
                .is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
            {
                tokio::task::block_in_place(do_wait);
            } else {
                do_wait();
            }
        }

        fn release(&self) {
            let (lock, cvar) = &*self.released;
            let mut flag = lock.lock().expect("lock canary gate released");
            *flag = true;
            cvar.notify_all();
        }
    }

    struct GatedCanaryNotifier {
        gate1: CanaryGate,
        gate2: CanaryGate,
        gate3: CanaryGate,
    }

    impl NotificationDispatcher for GatedCanaryNotifier {
        fn notify_alert(&self, alert: &AlertRecord) -> Result<(), String> {
            if alert.context_json.contains("gate1_canary") {
                self.gate1.wait_inside();
            } else if alert.context_json.contains("gate2_canary") {
                self.gate2.wait_inside();
            } else if alert.context_json.contains("gate3_canary") {
                self.gate3.wait_inside();
            }
            Ok(())
        }
    }

    struct CountingBurstMotwInspector {
        zones: HashMap<String, MotwZoneInfo>,
        seed_calls: Arc<(Mutex<usize>, Condvar)>,
        rt_calls: Arc<(Mutex<usize>, Condvar)>,
    }

    impl MotwInspector for CountingBurstMotwInspector {
        fn read_zone_identifier(&self, path: &Path) -> Option<MotwZoneInfo> {
            let normalized = path.display().to_string().replace('/', "\\");
            let found = self.zones.get(&normalized).cloned();
            if normalized.contains(r"\seed_") {
                let (lock, cvar) = &*self.seed_calls;
                let mut count = lock.lock().expect("lock seed_calls");
                *count += 1;
                cvar.notify_all();
            } else if normalized.contains(r"\rt_") {
                let (lock, cvar) = &*self.rt_calls;
                let mut count = lock.lock().expect("lock rt_calls");
                *count += 1;
                cvar.notify_all();
            }
            found
        }
    }

    const SEED_COUNT: usize = 64;
    const WAVE1_COUNT: usize = 50;
    const WAVE2_COUNT: usize = 40;
    const RT_TOTAL: usize = WAVE1_COUNT + WAVE2_COUNT; // 90 > MOTW_PENDING_LATE_CAPACITY (66)
    const EXPECTED_TOTAL: usize = SEED_COUNT + RT_TOTAL; // 154

    let base_ms = 1_760_023_000_000i64;
    let mut zones: HashMap<String, MotwZoneInfo> = HashMap::with_capacity(EXPECTED_TOTAL);
    let mut expected_origins: HashMap<String, String> = HashMap::with_capacity(EXPECTED_TOTAL);
    let mut seed_events: Vec<SensorEvent> = Vec::with_capacity(SEED_COUNT);

    for i in 0..SEED_COUNT {
        let exe = format!(r"C:\SeedBurst23\seed_{i:02}.exe");
        let url = format!("https://seed23.example.invalid/seed_{i:02}.exe");
        zones.insert(
            exe.clone(),
            MotwZoneInfo {
                zone_id: 3,
                host_url: Some(url.clone()),
                referrer_url: Some("https://seed23-ref.example.invalid/".to_string()),
            },
        );
        let ident = ProcessIdentity::new(41_000 + i as u32, unix_ms_to_filetime(base_ms + i as i64));
        expected_origins.insert(ident.instance_id(), url);
        seed_events.push(SensorEvent::ProcessStart {
            identity: ident,
            parent_pid: 4,
            exe_path: exe,
            command_line: format!("seed_{i:02}.exe"),
            user_sid: None,
        });
    }

    let mut rt_events: Vec<SensorEvent> = Vec::with_capacity(RT_TOTAL);
    for i in 0..RT_TOTAL {
        let exe = format!(r"C:\RtBurst23\rt_{i:02}.exe");
        let url = format!("https://rt23.example.invalid/rt_{i:02}.exe");
        zones.insert(
            exe.clone(),
            MotwZoneInfo {
                zone_id: 3,
                host_url: Some(url.clone()),
                referrer_url: Some("https://rt23-ref.example.invalid/".to_string()),
            },
        );
        let ident = ProcessIdentity::new(
            42_000 + i as u32,
            unix_ms_to_filetime(base_ms + 10_000 + i as i64),
        );
        expected_origins.insert(ident.instance_id(), url);
        rt_events.push(SensorEvent::ProcessStart {
            identity: ident,
            parent_pid: 4,
            exe_path: exe,
            command_line: format!("rt_{i:02}.exe"),
            user_sid: None,
        });
    }

    let dir = TestTempDir::new("p4-23");
    let dl_file = dir.0.join("urgent_p4_23_dl.exe");
    std::fs::write(&dl_file, b"p4-23-urgent-download-payload-for-sha256")
        .expect("write urgent_p4_23_dl.exe");
    let expected_dl_sha = compute_file_sha256_hex(&dl_file).expect("hash urgent_p4_23_dl.exe");
    let dl_path_str = dl_file.display().to_string();

    let (gate1, _gate1_guard) = CanaryGate::new();
    let (gate2, _gate2_guard) = CanaryGate::new();
    let (gate3, _gate3_guard) = CanaryGate::new();
    let notifier = Arc::new(GatedCanaryNotifier {
        gate1: gate1.clone(),
        gate2: gate2.clone(),
        gate3: gate3.clone(),
    });

    let seed_calls = Arc::new((Mutex::new(0usize), Condvar::new()));
    let rt_calls = Arc::new((Mutex::new(0usize), Condvar::new()));
    let motw_inspector = Arc::new(CountingBurstMotwInspector {
        zones,
        seed_calls: Arc::clone(&seed_calls),
        rt_calls: Arc::clone(&rt_calls),
    });

    let pipe_name = unique_test_pipe_name();
    let store = LedrStore::open_in_memory().expect("open store");
    let engine = DaemonEngine::start_with_motw_inspector(
        store.clone(),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: pipe_name.clone(),
            dev_mode_bypass_ui_auth: true,
            ipc_session_timeout_ms: 1_500,
            motw_sync_wait_budget_ms: 0,
            shutdown_flush_timeout_ms: 3_000,
            ..DaemonConfig::default()
        },
        Arc::new(MockDefense::new()),
        notifier.clone(),
        Arc::new(WindowsBinaryInspector::new()),
        Arc::new(NullLiveProcessInspector),
        motw_inspector,
    );
    let ipc = start_ipc_server(Arc::clone(&engine)).expect("bind IPC pipe");
    let sender = engine.sender();

    // 1. Hold `run_pipeline` at Gate 1 (`CanaryFileAccess`), preventing `motw_result_rx` drains.
    sender
        .send(SensorEvent::CanaryFileAccess {
            pid: 99_001,
            target_path: r"C:\Temp\gate1_canary.docx".to_string(),
            category: CanaryCategory::Honeypot,
            access_mask: 2,
            is_write_or_delete: true,
            timestamp_ms: base_ms + 1,
        })
        .await
        .expect("send gate1 canary");
    let g1_wait = Arc::clone(&gate1.entered);
    tokio::task::spawn_blocking(move || wait_count_reached(&g1_wait, 1))
        .await
        .expect("wait gate1 entered");

    // 2. Seed 64 startup MOTW groups to fill `motw_result_tx` (capacity 64).
    assert_eq!(
        engine.seed_processes(seed_events).expect("seed 64 MOTW groups"),
        SEED_COUNT
    );
    let seed_wait = Arc::clone(&seed_calls);
    tokio::task::spawn_blocking(move || wait_count_reached(&seed_wait, SEED_COUNT))
        .await
        .expect("wait 64 seeds resolved into motw_result_tx");

    // 3. Wave 1 (50 real-time ProcessStarts + Gate 2 canary): release Gate 1 so all 50 events
    //    enqueue into `process_queue` (< 64); 3 slots drain via Tier 1b interleave (high_priority_streak
    //    1 -> 51 => 3 drains) and 47 stash into `pending_late`, yielding `rt_calls == 50`.
    for event in rt_events.iter().take(WAVE1_COUNT).cloned() {
        sender.send(event).await.expect("send wave1 ProcessStart");
    }
    sender
        .send(SensorEvent::CanaryFileAccess {
            pid: 99_002,
            target_path: r"C:\Temp\gate2_canary.docx".to_string(),
            category: CanaryCategory::Honeypot,
            access_mask: 2,
            is_write_or_delete: true,
            timestamp_ms: base_ms + 2,
        })
        .await
        .expect("send gate2 canary");
    gate1.release();

    let g2_wait = Arc::clone(&gate2.entered);
    tokio::task::spawn_blocking(move || wait_count_reached(&g2_wait, 1))
        .await
        .expect("wait gate2 entered");
    let rt_wait_50 = Arc::clone(&rt_calls);
    tokio::task::spawn_blocking(move || wait_count_reached(&rt_wait_50, WAVE1_COUNT))
        .await
        .expect("wait wave1 50 real-time MOTW resolutions");

    // 4. Wave 2 (40 real-time ProcessStarts + Gate 3 canary, total 90 > pending_late cap 66):
    //    2 more drains occur via Tier 1b interleave (`streak` 4 -> 44 => 2 drains), bringing
    //    total capacity to 64 (channel) + 5 (drained) + 66 (pending_late) - 64 (seeds) = 71,
    //    while the remaining 19 stay queued in `process_queue` gated by late-slot reservation.
    for event in rt_events.iter().skip(WAVE1_COUNT).cloned() {
        sender.send(event).await.expect("send wave2 ProcessStart");
    }
    sender
        .send(SensorEvent::CanaryFileAccess {
            pid: 99_003,
            target_path: r"C:\Temp\gate3_canary.docx".to_string(),
            category: CanaryCategory::Honeypot,
            access_mask: 2,
            is_write_or_delete: true,
            timestamp_ms: base_ms + 3,
        })
        .await
        .expect("send gate3 canary");
    gate2.release();

    let g3_wait = Arc::clone(&gate3.entered);
    tokio::task::spawn_blocking(move || wait_count_reached(&g3_wait, 1))
        .await
        .expect("wait gate3 entered");
    let rt_wait_71 = Arc::clone(&rt_calls);
    tokio::task::spawn_blocking(move || wait_count_reached(&rt_wait_71, 71))
        .await
        .expect("wait 71 real-time MOTW resolutions under saturated pending_late");

    // 5. While Gate 3 holds `run_pipeline` and `motw_result_tx` (64/64) + `pending_late` (66/66)
    //    are both saturated with 19 jobs held in `process_queue`, IPC `ReportDownloadOrigin` must
    //    still preempt via `download_queue`, hash the real temp file, and Ack in < 1s.
    let dl_t0 = Instant::now();
    let pipe_for_dl = pipe_name.clone();
    let dl_req_path = dl_path_str.clone();
    let dl_resp = tokio::task::spawn_blocking(move || {
        send_pipe_request(
            &pipe_for_dl,
            &IpcRequest::ReportDownloadOrigin {
                file_path: dl_req_path,
                tab_url: "https://urgent-p4-23.example.invalid/dl.exe".to_string(),
                frame_url: None,
                referrer_url: Some("https://urgent-p4-23-ref.example.invalid/".to_string()),
                downloaded_at_ms: base_ms + 500,
            },
        )
    })
    .await
    .expect("join ReportDownloadOrigin client");
    let dl_elapsed = dl_t0.elapsed();
    assert!(
        matches!(dl_resp, IpcResponse::Ack { .. }),
        "IPC ReportDownloadOrigin must return Ack while MOTW queues are saturated: {dl_resp:?}"
    );
    assert!(
        dl_elapsed < Duration::from_secs(1),
        "IPC ReportDownloadOrigin took {dl_elapsed:?} under saturated MOTW burst"
    );

    let dl_snap = store
        .query_flight_recorder(10, None)
        .expect("query persisted download origin");
    assert_eq!(dl_snap.download_origins.len(), 1);
    assert_eq!(
        dl_snap.download_origins[0].sha256.as_deref(),
        Some(expected_dl_sha.as_str())
    );
    assert_eq!(
        dl_snap.download_origins[0].tab_url,
        "https://urgent-p4-23.example.invalid/dl.exe"
    );
    assert_eq!(
        *rt_calls.0.lock().expect("lock rt_calls during saturation"),
        71,
        "late-slot reservation gate must block the 72nd real-time lookup while pending_late is full"
    );
    assert_eq!(*seed_calls.0.lock().expect("lock seed_calls"), SEED_COUNT);

    // 6. Release Gate 3 and verify all 154 processes (64 seeds + 90 real-time launches) persist
    //    their `origin_url` with zero loss, zero HP drops, and clean shutdown within 3s budget.
    gate3.release();

    let persist_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let _ = store.flush_batch();
        let snap = store
            .query_flight_recorder(512, None)
            .expect("query persisted MOTW attributions");
        let matched = snap
            .processes
            .iter()
            .filter(|p| {
                expected_origins
                    .get(&p.process_instance_id)
                    .is_some_and(|exp| p.origin_url.as_deref() == Some(exp.as_str()))
            })
            .count();
        if matched == EXPECTED_TOTAL {
            break;
        }
        assert!(
            Instant::now() < persist_deadline,
            "timed out waiting for all {EXPECTED_TOTAL} MOTW origin_urls (matched={matched})"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    assert_eq!(*rt_calls.0.lock().expect("lock final rt_calls"), RT_TOTAL);
    assert_eq!(*seed_calls.0.lock().expect("lock final seed_calls"), SEED_COUNT);
    assert_eq!(engine.high_priority_dropped(), 0);

    ipc.shutdown().await;
    let shutdown_t0 = Instant::now();
    engine
        .shutdown_and_flush()
        .await
        .expect("shutdown_and_flush must complete cleanly within budget");
    assert!(
        shutdown_t0.elapsed() < Duration::from_secs(3),
        "shutdown_and_flush exceeded 3s budget: {:?}",
        shutdown_t0.elapsed()
    );

    let final_snap = store
        .query_flight_recorder(512, None)
        .expect("query final flight recorder");
    let final_matched = final_snap
        .processes
        .iter()
        .filter(|p| {
            expected_origins
                .get(&p.process_instance_id)
                .is_some_and(|exp| p.origin_url.as_deref() == Some(exp.as_str()))
        })
        .count();
    assert_eq!(
        final_matched, EXPECTED_TOTAL,
        "all {EXPECTED_TOTAL} MOTW attributions must persist with zero loss"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_p4_24_short_lived_process_during_saturated_pending_late_backfills_history_without_wfp()
{
    #[derive(Clone)]
    struct CanaryGate {
        entered: Arc<(Mutex<usize>, Condvar)>,
        released: Arc<(Mutex<bool>, Condvar)>,
    }

    impl CanaryGate {
        fn new() -> (Self, GateReleaseGuard) {
            let entered = Arc::new((Mutex::new(0usize), Condvar::new()));
            let released = Arc::new((Mutex::new(false), Condvar::new()));
            let guard = GateReleaseGuard(Arc::clone(&released));
            (Self { entered, released }, guard)
        }

        fn wait_inside(&self) {
            let do_wait = || {
                {
                    let (lock, cvar) = &*self.entered;
                    let mut count = lock.lock().expect("lock canary gate entered");
                    *count += 1;
                    cvar.notify_all();
                }
                {
                    let (lock, cvar) = &*self.released;
                    let mut flag = lock.lock().expect("lock canary gate released");
                    while !*flag {
                        flag = cvar.wait(flag).expect("wait canary gate released");
                    }
                }
            };
            // Yield the Tokio worker slot before blocking on a Condvar so the multi-threaded
            // runtime's timer driver remains responsive while `run_pipeline` is paused.
            if tokio::runtime::Handle::try_current()
                .is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
            {
                tokio::task::block_in_place(do_wait);
            } else {
                do_wait();
            }
        }

        fn release(&self) {
            let (lock, cvar) = &*self.released;
            let mut flag = lock.lock().expect("lock canary gate released");
            *flag = true;
            cvar.notify_all();
        }
    }

    struct GatedCanaryNotifier {
        gate1: CanaryGate,
        gate2: CanaryGate,
        gate3: CanaryGate,
        gate4: CanaryGate,
    }

    impl NotificationDispatcher for GatedCanaryNotifier {
        fn notify_alert(&self, alert: &AlertRecord) -> Result<(), String> {
            if alert.context_json.contains("gate1_canary") {
                self.gate1.wait_inside();
            } else if alert.context_json.contains("gate2_canary") {
                self.gate2.wait_inside();
            } else if alert.context_json.contains("gate3_canary") {
                self.gate3.wait_inside();
            } else if alert.context_json.contains("gate4_canary") {
                self.gate4.wait_inside();
            }
            Ok(())
        }
    }

    struct TwoWaveSlowMotwInspector {
        zones: HashMap<String, MotwZoneInfo>,
        slow_gate_a: Arc<(Mutex<bool>, Condvar)>,
        slow_gate_b: Arc<(Mutex<bool>, Condvar)>,
        seed_calls: Arc<(Mutex<usize>, Condvar)>,
        fill_calls: Arc<(Mutex<usize>, Condvar)>,
        short_lived_calls: Arc<(Mutex<usize>, Condvar)>,
        preexisting_calls: Arc<(Mutex<usize>, Condvar)>,
        tail_calls: Arc<(Mutex<usize>, Condvar)>,
    }

    impl TwoWaveSlowMotwInspector {
        fn wait_gate(gate: &(Mutex<bool>, Condvar)) {
            let (lock, cvar) = gate;
            let mut released = lock.lock().expect("lock slow gate");
            while !*released {
                released = cvar.wait(released).expect("wait slow gate");
            }
        }

        fn bump(counter: &(Mutex<usize>, Condvar)) {
            let (lock, cvar) = counter;
            let mut count = lock.lock().expect("lock motw call counter");
            *count += 1;
            cvar.notify_all();
        }
    }

    impl MotwInspector for TwoWaveSlowMotwInspector {
        fn read_zone_identifier(&self, path: &Path) -> Option<MotwZoneInfo> {
            let normalized = path.display().to_string().replace('/', "\\");
            if normalized.ends_with(r"\slow_probe_0.exe")
                || normalized.ends_with(r"\slow_probe_1.exe")
            {
                Self::wait_gate(&self.slow_gate_a);
            } else if normalized.ends_with(r"\slow_probe_2.exe")
                || normalized.ends_with(r"\slow_probe_3.exe")
            {
                Self::wait_gate(&self.slow_gate_b);
            }

            let found = self.zones.get(&normalized).cloned();
            if normalized.contains(r"\seed_") {
                Self::bump(&self.seed_calls);
            } else if normalized.contains(r"\slow_probe_") || normalized.contains(r"\fill_") {
                Self::bump(&self.fill_calls);
            } else if normalized.ends_with(r"\short_lived_tool.exe") {
                Self::bump(&self.short_lived_calls);
            } else if normalized.ends_with(r"\preexisting_exited.exe") {
                Self::bump(&self.preexisting_calls);
            } else if normalized.contains(r"\tail_active_") {
                Self::bump(&self.tail_calls);
            }
            found
        }
    }

    const SEED_COUNT: usize = 64;
    const WAVE1_FILL_COUNT: usize = 46; // + 2 slow probes = 48 Wave 1 events
    const WAVE2_FILL_COUNT: usize = 20; // + 2 slow probes = 22 Wave 2 events
    const WAVE1_TOTAL: usize = 2 + WAVE1_FILL_COUNT; // 48
    const WAVE2_TOTAL: usize = 2 + WAVE2_FILL_COUNT; // 22
    const FILL_TOTAL: usize = WAVE1_TOTAL + WAVE2_TOTAL; // 70
    // 64 seeds + 70 fills + 1 short_lived_tool + 1 preexisting_exited + 2 tail_active = 138
    const EXPECTED_TOTAL: usize = SEED_COUNT + FILL_TOTAL + 4;

    let base_ms = 1_760_024_000_000i64;
    let mut zones: HashMap<String, MotwZoneInfo> = HashMap::with_capacity(EXPECTED_TOTAL);
    let mut expected_origins: HashMap<String, String> = HashMap::with_capacity(EXPECTED_TOTAL);

    let mut seed_events: Vec<SensorEvent> = Vec::with_capacity(SEED_COUNT);
    for i in 0..SEED_COUNT {
        let exe = format!(r"C:\SeedSat24\seed_{i:02}.exe");
        let url = format!("https://seed24.example.invalid/seed_{i:02}.exe");
        zones.insert(
            exe.clone(),
            MotwZoneInfo {
                zone_id: 3,
                host_url: Some(url.clone()),
                referrer_url: Some("https://seed24-ref.example.invalid/".to_string()),
            },
        );
        let ident = ProcessIdentity::new(43_000 + i as u32, unix_ms_to_filetime(base_ms + i as i64));
        expected_origins.insert(ident.instance_id(), url);
        seed_events.push(SensorEvent::ProcessStart {
            identity: ident,
            parent_pid: 4,
            exe_path: exe,
            command_line: format!("seed_{i:02}.exe"),
            user_sid: None,
        });
    }

    let mut wave1_events: Vec<SensorEvent> = Vec::with_capacity(WAVE1_TOTAL);
    for probe_idx in 0..2usize {
        let exe = format!(r"C:\FillSat24\slow_probe_{probe_idx}.exe");
        let url = format!("https://fill24.example.invalid/slow_probe_{probe_idx}.exe");
        zones.insert(
            exe.clone(),
            MotwZoneInfo {
                zone_id: 3,
                host_url: Some(url.clone()),
                referrer_url: Some("https://fill24-ref.example.invalid/".to_string()),
            },
        );
        let ident = ProcessIdentity::new(
            44_000 + probe_idx as u32,
            unix_ms_to_filetime(base_ms + 10_000 + probe_idx as i64),
        );
        expected_origins.insert(ident.instance_id(), url);
        wave1_events.push(SensorEvent::ProcessStart {
            identity: ident,
            parent_pid: 4,
            exe_path: exe,
            command_line: format!("slow_probe_{probe_idx}.exe"),
            user_sid: None,
        });
    }
    for i in 0..WAVE1_FILL_COUNT {
        let exe = format!(r"C:\FillSat24\fill_{i:02}.exe");
        let url = format!("https://fill24.example.invalid/fill_{i:02}.exe");
        zones.insert(
            exe.clone(),
            MotwZoneInfo {
                zone_id: 3,
                host_url: Some(url.clone()),
                referrer_url: Some("https://fill24-ref.example.invalid/".to_string()),
            },
        );
        let ident = ProcessIdentity::new(
            44_010 + i as u32,
            unix_ms_to_filetime(base_ms + 10_100 + i as i64),
        );
        expected_origins.insert(ident.instance_id(), url);
        wave1_events.push(SensorEvent::ProcessStart {
            identity: ident,
            parent_pid: 4,
            exe_path: exe,
            command_line: format!("fill_{i:02}.exe"),
            user_sid: None,
        });
    }

    let mut wave2_events: Vec<SensorEvent> = Vec::with_capacity(WAVE2_TOTAL);
    for probe_idx in 2..4usize {
        let exe = format!(r"C:\FillSat24\slow_probe_{probe_idx}.exe");
        let url = format!("https://fill24.example.invalid/slow_probe_{probe_idx}.exe");
        zones.insert(
            exe.clone(),
            MotwZoneInfo {
                zone_id: 3,
                host_url: Some(url.clone()),
                referrer_url: Some("https://fill24-ref.example.invalid/".to_string()),
            },
        );
        let ident = ProcessIdentity::new(
            44_000 + probe_idx as u32,
            unix_ms_to_filetime(base_ms + 11_000 + probe_idx as i64),
        );
        expected_origins.insert(ident.instance_id(), url);
        wave2_events.push(SensorEvent::ProcessStart {
            identity: ident,
            parent_pid: 4,
            exe_path: exe,
            command_line: format!("slow_probe_{probe_idx}.exe"),
            user_sid: None,
        });
    }
    for i in WAVE1_FILL_COUNT..(WAVE1_FILL_COUNT + WAVE2_FILL_COUNT) {
        let exe = format!(r"C:\FillSat24\fill_{i:02}.exe");
        let url = format!("https://fill24.example.invalid/fill_{i:02}.exe");
        zones.insert(
            exe.clone(),
            MotwZoneInfo {
                zone_id: 3,
                host_url: Some(url.clone()),
                referrer_url: Some("https://fill24-ref.example.invalid/".to_string()),
            },
        );
        let ident = ProcessIdentity::new(
            44_010 + i as u32,
            unix_ms_to_filetime(base_ms + 11_100 + i as i64),
        );
        expected_origins.insert(ident.instance_id(), url);
        wave2_events.push(SensorEvent::ProcessStart {
            identity: ident,
            parent_pid: 4,
            exe_path: exe,
            command_line: format!("fill_{i:02}.exe"),
            user_sid: None,
        });
    }

    let short_lived_exe = r"C:\ShortLived24\short_lived_tool.exe";
    let short_lived_url = "https://short-lived.example.invalid/tool.exe";
    zones.insert(
        short_lived_exe.to_string(),
        MotwZoneInfo {
            zone_id: 3,
            host_url: Some(short_lived_url.to_string()),
            referrer_url: Some("https://short-lived-ref.example.invalid/".to_string()),
        },
    );
    let short_lived_ident = ProcessIdentity::new(45_001, unix_ms_to_filetime(base_ms + 20_000));
    expected_origins.insert(
        short_lived_ident.instance_id(),
        short_lived_url.to_string(),
    );

    let preexisting_exe = r"C:\ShortLived24\preexisting_exited.exe";
    let preexisting_keep_url = "https://preexisting-origin.example.invalid/keep.exe";
    zones.insert(
        preexisting_exe.to_string(),
        MotwZoneInfo {
            zone_id: 3,
            host_url: Some("https://late-overwrite-attempt.example.invalid/keep.exe".to_string()),
            referrer_url: None,
        },
    );
    let preexisting_ident = ProcessIdentity::new(45_002, unix_ms_to_filetime(base_ms + 20_020));
    expected_origins.insert(
        preexisting_ident.instance_id(),
        preexisting_keep_url.to_string(),
    );

    let tail1_exe = r"C:\ShortLived24\tail_active_1.exe";
    let tail1_url = "https://tail24.example.invalid/tail_active_1.exe";
    zones.insert(
        tail1_exe.to_string(),
        MotwZoneInfo {
            zone_id: 3,
            host_url: Some(tail1_url.to_string()),
            referrer_url: None,
        },
    );
    let tail1_ident = ProcessIdentity::new(45_003, unix_ms_to_filetime(base_ms + 20_040));
    expected_origins.insert(tail1_ident.instance_id(), tail1_url.to_string());

    let tail2_exe = r"C:\ShortLived24\tail_active_2.exe";
    let tail2_url = "https://tail24.example.invalid/tail_active_2.exe";
    zones.insert(
        tail2_exe.to_string(),
        MotwZoneInfo {
            zone_id: 3,
            host_url: Some(tail2_url.to_string()),
            referrer_url: None,
        },
    );
    let tail2_ident = ProcessIdentity::new(45_004, unix_ms_to_filetime(base_ms + 20_060));
    expected_origins.insert(tail2_ident.instance_id(), tail2_url.to_string());

    let (gate1, _gate1_guard) = CanaryGate::new();
    let (gate2, _gate2_guard) = CanaryGate::new();
    let (gate3, _gate3_guard) = CanaryGate::new();
    let (gate4, _gate4_guard) = CanaryGate::new();
    let notifier = Arc::new(GatedCanaryNotifier {
        gate1: gate1.clone(),
        gate2: gate2.clone(),
        gate3: gate3.clone(),
        gate4: gate4.clone(),
    });

    let slow_gate_a = Arc::new((Mutex::new(false), Condvar::new()));
    let slow_gate_b = Arc::new((Mutex::new(false), Condvar::new()));
    let _slow_gate_a_guard = GateReleaseGuard(Arc::clone(&slow_gate_a));
    let _slow_gate_b_guard = GateReleaseGuard(Arc::clone(&slow_gate_b));

    let seed_calls = Arc::new((Mutex::new(0usize), Condvar::new()));
    let fill_calls = Arc::new((Mutex::new(0usize), Condvar::new()));
    let short_lived_calls = Arc::new((Mutex::new(0usize), Condvar::new()));
    let preexisting_calls = Arc::new((Mutex::new(0usize), Condvar::new()));
    let tail_calls = Arc::new((Mutex::new(0usize), Condvar::new()));
    let motw_inspector = Arc::new(TwoWaveSlowMotwInspector {
        zones,
        slow_gate_a: Arc::clone(&slow_gate_a),
        slow_gate_b: Arc::clone(&slow_gate_b),
        seed_calls: Arc::clone(&seed_calls),
        fill_calls: Arc::clone(&fill_calls),
        short_lived_calls: Arc::clone(&short_lived_calls),
        preexisting_calls: Arc::clone(&preexisting_calls),
        tail_calls: Arc::clone(&tail_calls),
    });

    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockDefense::new());
    let engine = DaemonEngine::start_with_motw_inspector(
        store.clone(),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            dev_mode_bypass_ui_auth: true,
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::Enforce,
            motw_sync_wait_budget_ms: 20,
            shutdown_flush_timeout_ms: 3_000,
            ..DaemonConfig::default()
        },
        defense.clone(),
        notifier,
        Arc::new(MapBinaryInspector::default()),
        Arc::new(NullLiveProcessInspector),
        motw_inspector,
    );
    let sender = engine.sender();

    // 1. Hold `run_pipeline` at Gate 1 and saturate `motw_result_tx` (64/64) with seed groups.
    sender
        .send(SensorEvent::CanaryFileAccess {
            pid: 99_001,
            target_path: r"C:\Temp\gate1_canary.docx".to_string(),
            category: CanaryCategory::Honeypot,
            access_mask: 2,
            is_write_or_delete: true,
            timestamp_ms: base_ms + 1,
        })
        .await
        .expect("send gate1 canary");
    let g1_wait = Arc::clone(&gate1.entered);
    tokio::task::spawn_blocking(move || wait_count_reached(&g1_wait, 1))
        .await
        .expect("wait gate1 entered");

    async fn wait_motw_pool_counts(
        engine: &DaemonEngine,
        expected: (usize, usize, usize, usize, usize, usize),
        label: &str,
    ) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let actual = engine.motw_pool_queue_counts();
            if actual == expected {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for MOTW pool state [{label}]: expected={expected:?} actual={actual:?}"
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    assert_eq!(
        engine.seed_processes(seed_events).expect("seed 64 MOTW groups"),
        SEED_COUNT
    );
    let seed_wait = Arc::clone(&seed_calls);
    tokio::task::spawn_blocking(move || wait_count_reached(&seed_wait, SEED_COUNT))
        .await
        .expect("wait 64 seeds resolved into motw_result_tx");
    wait_motw_pool_counts(&engine, (0, 0, 0, 0, 0, 0), "seeds_idle").await;

    // 2. Wave 1 (2 slow probes + 46 fills = 48 ProcessStarts + Gate 2 canary):
    //    `slow_probe_0` and `slow_probe_1` exceed the 20 ms sync wait budget while wedged at
    //    `slow_gate_a`, forcing `fill_00..fill_45` to queue asynchronously. Exactly 3 Tier 1b
    //    drains occur across the 48 events; after releasing `slow_gate_a`, `pending_late` holds
    //    45/66 items and `process_queue` is empty.
    for event in wave1_events {
        sender.send(event).await.expect("send wave1 ProcessStart");
    }
    sender
        .send(SensorEvent::CanaryFileAccess {
            pid: 99_002,
            target_path: r"C:\Temp\gate2_canary.docx".to_string(),
            category: CanaryCategory::Honeypot,
            access_mask: 2,
            is_write_or_delete: true,
            timestamp_ms: base_ms + 2,
        })
        .await
        .expect("send gate2 canary");
    gate1.release();

    let g2_wait = Arc::clone(&gate2.entered);
    tokio::task::spawn_blocking(move || wait_count_reached(&g2_wait, 1))
        .await
        .expect("wait gate2 entered");
    {
        let (lock, cvar) = &*slow_gate_a;
        let mut flag = lock.lock().expect("lock slow_gate_a");
        *flag = true;
        cvar.notify_all();
    }
    let fill_wait_48 = Arc::clone(&fill_calls);
    tokio::task::spawn_blocking(move || wait_count_reached(&fill_wait_48, WAVE1_TOTAL))
        .await
        .expect("wait wave1 48 fill MOTW resolutions");
    wait_motw_pool_counts(&engine, (45, 0, 0, 0, 0, 0), "wave1_idle").await;

    // 3. Wave 2 (2 slow probes + 20 fills = 22 ProcessStarts + Gate 3 canary):
    //    Exactly 1 Tier 1b drain occurs across the 22 events. Releasing `slow_gate_b` fills
    //    `pending_late` to exactly 64 + 70 - 4 - 64 = 66/66 with `process_queue` empty and both
    //    MOTW workers idle.
    for event in wave2_events {
        sender.send(event).await.expect("send wave2 ProcessStart");
    }
    sender
        .send(SensorEvent::CanaryFileAccess {
            pid: 99_003,
            target_path: r"C:\Temp\gate3_canary.docx".to_string(),
            category: CanaryCategory::Honeypot,
            access_mask: 2,
            is_write_or_delete: true,
            timestamp_ms: base_ms + 3,
        })
        .await
        .expect("send gate3 canary");
    gate2.release();

    let g3_wait = Arc::clone(&gate3.entered);
    tokio::task::spawn_blocking(move || wait_count_reached(&g3_wait, 1))
        .await
        .expect("wait gate3 entered");
    {
        let (lock, cvar) = &*slow_gate_b;
        let mut flag = lock.lock().expect("lock slow_gate_b");
        *flag = true;
        cvar.notify_all();
    }
    let fill_wait_70 = Arc::clone(&fill_calls);
    tokio::task::spawn_blocking(move || wait_count_reached(&fill_wait_70, FILL_TOTAL))
        .await
        .expect("wait wave2 70 total fill MOTW resolutions");
    // Deterministically confirm `pending_late` 66/66 full, queues empty, `reserved_late_slots == 0`,
    // and `busy_workers == 0` BEFORE releasing Gate 3 so Wave 3 defers solely via `has_late_slot == false`.
    wait_motw_pool_counts(&engine, (66, 0, 0, 0, 0, 0), "wave2_saturated_idle").await;
    assert_eq!(
        engine.motw_pool_queue_counts(),
        (66, 0, 0, 0, 0, 0),
        "precondition failed: pending_late must be 66/66 full with queues empty and workers idle"
    );

    // 4. Wave 3: While `pending_late` is 66/66 full and `process_queue` is empty, launch and
    //    immediately stop two short-lived processes (`preexisting_exited.exe` and
    //    `short_lived_tool.exe`) plus two active tail sentinels, then pause at Gate 4.
    //    6 events before `gate4_canary` stay below the 16-event Tier 1b interleave threshold
    //    (streak reaches 14 or 15 < 16), so zero drains occur before Gate 4.
    sender
        .send(SensorEvent::ProcessStart {
            identity: preexisting_ident,
            parent_pid: 4,
            exe_path: preexisting_exe.to_string(),
            command_line: "preexisting_exited.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send preexisting_exited ProcessStart");
    sender
        .send(SensorEvent::ProcessStop {
            pid: preexisting_ident.pid,
            exit_code: 0,
            exit_time_100ns: unix_ms_to_filetime(base_ms + 20_030),
        })
        .await
        .expect("send preexisting_exited ProcessStop");
    sender
        .send(SensorEvent::ProcessStart {
            identity: short_lived_ident,
            parent_pid: 4,
            exe_path: short_lived_exe.to_string(),
            command_line: "short_lived_tool.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send short_lived_tool ProcessStart");
    sender
        .send(SensorEvent::ProcessStop {
            pid: short_lived_ident.pid,
            exit_code: 0,
            exit_time_100ns: unix_ms_to_filetime(base_ms + 20_010),
        })
        .await
        .expect("send short_lived_tool ProcessStop");
    sender
        .send(SensorEvent::ProcessStart {
            identity: tail1_ident,
            parent_pid: 4,
            exe_path: tail1_exe.to_string(),
            command_line: "tail_active_1.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send tail_active_1 ProcessStart");
    sender
        .send(SensorEvent::ProcessStart {
            identity: tail2_ident,
            parent_pid: 4,
            exe_path: tail2_exe.to_string(),
            command_line: "tail_active_2.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send tail_active_2 ProcessStart");
    sender
        .send(SensorEvent::CanaryFileAccess {
            pid: 99_004,
            target_path: r"C:\Temp\gate4_canary.docx".to_string(),
            category: CanaryCategory::Honeypot,
            access_mask: 2,
            is_write_or_delete: true,
            timestamp_ms: base_ms + 4,
        })
        .await
        .expect("send gate4 canary");
    gate3.release();

    let g4_wait = Arc::clone(&gate4.entered);
    tokio::task::spawn_blocking(move || wait_count_reached(&g4_wait, 1))
        .await
        .expect("wait gate4 entered");

    // Verify full `pending_late` deferred synchronous MOTW wait even with `motw_sync_wait_budget_ms > 0`,
    // and both short-lived processes have already exited in SQLite with `origin_url == None`.
    assert_eq!(
        engine.motw_pool_queue_counts(),
        (66, 4, 0, 0, 0, 0),
        "all 4 Wave 3 processes must remain queued behind saturated pending_late with idle workers"
    );
    assert_eq!(
        *short_lived_calls
            .0
            .lock()
            .expect("lock short_lived_calls at gate4"),
        0,
        "short_lived_tool.exe must remain deferred while pending_late is saturated"
    );
    assert_eq!(
        *preexisting_calls
            .0
            .lock()
            .expect("lock preexisting_calls at gate4"),
        0,
        "preexisting_exited.exe must remain deferred while pending_late is saturated"
    );
    assert_eq!(
        *tail_calls.0.lock().expect("lock tail_calls at gate4"),
        0,
        "tail active sentinels must remain deferred while pending_late is saturated"
    );

    store.flush_batch().expect("flush batch at gate4");
    let pre_short_snap = store
        .query_flight_recorder(10, Some(&short_lived_ident.instance_id()))
        .expect("query short_lived_tool at gate4");
    assert_eq!(pre_short_snap.processes.len(), 1);
    assert!(
        pre_short_snap.processes[0].exited_at_ms.is_some(),
        "short_lived_tool.exe must already be marked exited before late MOTW resolves"
    );
    assert_eq!(
        pre_short_snap.processes[0].origin_url, None,
        "short_lived_tool.exe must not yet have origin_url while deferred"
    );

    let pre_existing_snap = store
        .query_flight_recorder(10, Some(&preexisting_ident.instance_id()))
        .expect("query preexisting_exited at gate4");
    assert_eq!(pre_existing_snap.processes.len(), 1);
    assert!(pre_existing_snap.processes[0].exited_at_ms.is_some());
    assert_eq!(pre_existing_snap.processes[0].origin_url, None);

    // Pre-populate SQLite `origin_url` for `preexisting_exited.exe` while its table entry still
    // has `origin_url == None`, verifying delayed backfill uses `COALESCE` without overwriting.
    assert!(
        store
            .update_process_motw_metadata(
                &preexisting_ident.instance_id(),
                Some(preexisting_keep_url),
                None,
            )
            .expect("seed preexisting SQLite origin_url"),
        "preexisting_exited row must exist in SQLite before Gate 4 release"
    );

    // 5. Release Gate 4 and verify delayed MOTW drains cleanly, backfills SQLite history for
    //    `short_lived_tool.exe`, preserves `preexisting_exited.exe` via `COALESCE`, grants zero
    //    L-18 WFP blocks to exited processes, and persists all 138 processes with zero loss.
    gate4.release();

    let sl_wait = Arc::clone(&short_lived_calls);
    tokio::task::spawn_blocking(move || wait_count_reached(&sl_wait, 1))
        .await
        .expect("wait short_lived_tool MOTW lookup");
    let pre_wait = Arc::clone(&preexisting_calls);
    tokio::task::spawn_blocking(move || wait_count_reached(&pre_wait, 1))
        .await
        .expect("wait preexisting_exited MOTW lookup");
    let tail_wait = Arc::clone(&tail_calls);
    tokio::task::spawn_blocking(move || wait_count_reached(&tail_wait, 2))
        .await
        .expect("wait tail active sentinels MOTW lookups");

    let persist_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let _ = store.flush_batch();
        let snap = store
            .query_flight_recorder(512, None)
            .expect("query persisted MOTW attributions");
        let matched = snap
            .processes
            .iter()
            .filter(|p| {
                expected_origins
                    .get(&p.process_instance_id)
                    .is_some_and(|exp| p.origin_url.as_deref() == Some(exp.as_str()))
            })
            .count();
        let wfp_calls = defense.added_wfp();
        let active_wfp_applied = wfp_calls
            .iter()
            .any(|c| c.exe_path.ends_with("tail_active_1.exe"))
            && wfp_calls
                .iter()
                .any(|c| c.exe_path.ends_with("tail_active_2.exe"))
            && wfp_calls.iter().any(|c| c.exe_path.ends_with("seed_00.exe"))
            && wfp_calls.iter().any(|c| c.exe_path.ends_with("fill_00.exe"));
        let pool_idle = engine.motw_pool_queue_counts() == (0, 0, 0, 0, 0, 0);
        if matched == EXPECTED_TOTAL && active_wfp_applied && pool_idle {
            break;
        }
        assert!(
            Instant::now() < persist_deadline,
            "timed out waiting for all {EXPECTED_TOTAL} MOTW origin_urls, active WFP blocks, and idle pool (matched={matched}, active_wfp_applied={active_wfp_applied}, pool={:?})",
            engine.motw_pool_queue_counts()
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    assert_eq!(engine.high_priority_dropped(), 0);

    let shutdown_t0 = Instant::now();
    engine
        .shutdown_and_flush()
        .await
        .expect("shutdown_and_flush must complete cleanly within budget");
    assert!(
        shutdown_t0.elapsed() < Duration::from_secs(3),
        "shutdown_and_flush exceeded 3s budget: {:?}",
        shutdown_t0.elapsed()
    );

    // Verify all history, COALESCE preservation, and negative/positive WFP invariants AFTER
    // `shutdown_and_flush` guarantees `motw_result_rx` (including `preexisting_exited.exe`)
    // has completely drained through `apply_late_motw_attribution`.
    let post_short_snap = store
        .query_flight_recorder(10, Some(&short_lived_ident.instance_id()))
        .expect("query short_lived_tool after drain");
    assert_eq!(post_short_snap.processes.len(), 1);
    assert_eq!(
        post_short_snap.processes[0].origin_url.as_deref(),
        Some(short_lived_url),
        "short_lived_tool.exe must backfill SQLite origin_url after exiting"
    );
    assert!(
        post_short_snap.processes[0].exited_at_ms.is_some(),
        "short_lived_tool.exe must retain exited_at_ms after SQLite history backfill"
    );

    let post_preexisting_snap = store
        .query_flight_recorder(10, Some(&preexisting_ident.instance_id()))
        .expect("query preexisting_exited after drain");
    assert_eq!(post_preexisting_snap.processes.len(), 1);
    assert_eq!(
        post_preexisting_snap.processes[0].origin_url.as_deref(),
        Some(preexisting_keep_url),
        "delayed MOTW backfill must not overwrite an existing SQLite origin_url (COALESCE)"
    );
    assert!(post_preexisting_snap.processes[0].exited_at_ms.is_some());

    let wfp_calls = defense.added_wfp();
    assert!(
        !wfp_calls
            .iter()
            .any(|c| c.exe_path.ends_with("short_lived_tool.exe")),
        "exited short_lived_tool.exe must not receive an L-18 pre-emptive WFP block"
    );
    assert!(
        !wfp_calls
            .iter()
            .any(|c| c.exe_path.ends_with("preexisting_exited.exe")),
        "exited preexisting_exited.exe must not receive an L-18 pre-emptive WFP block"
    );
    assert!(
        wfp_calls.iter().any(|c| c.exe_path.ends_with("tail_active_1.exe"))
            && wfp_calls.iter().any(|c| c.exe_path.ends_with("tail_active_2.exe"))
            && wfp_calls.iter().any(|c| c.exe_path.ends_with("seed_00.exe"))
            && wfp_calls.iter().any(|c| c.exe_path.ends_with("fill_00.exe")),
        "active MOTW processes must still receive L-18 pre-emptive WFP blocks"
    );

    let final_snap = store
        .query_flight_recorder(512, None)
        .expect("query final flight recorder");
    let final_matched = final_snap
        .processes
        .iter()
        .filter(|p| {
            expected_origins
                .get(&p.process_instance_id)
                .is_some_and(|exp| p.origin_url.as_deref() == Some(exp.as_str()))
        })
        .count();
    assert_eq!(
        final_matched, EXPECTED_TOTAL,
        "all {EXPECTED_TOTAL} processes must preserve their expected origin_url with zero loss"
    );
}

#[tokio::test]
async fn daemon_p4_25_expired_suspended_layer4_browser_alert_resolves_allow_once() {
    let defense = Arc::new(MockDefense::new());
    let store = LedrStore::open_in_memory().expect("open store");
    let pipe_name = unique_test_pipe_name();
    let engine = DaemonEngine::start_with_motw_inspector(
        store.clone(),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: pipe_name.clone(),
            dev_mode_bypass_ui_auth: true,
            strict_pipe_dacl: false,
            ..DaemonConfig::default()
        },
        defense.clone(),
        Arc::new(RecordingNotifier::default()),
        Arc::new(MapBinaryInspector::default()),
        Arc::new(NullLiveProcessInspector),
        Arc::new(MapMotwInspector::default()),
    );

    let event_ts = 1_760_099_000_000;
    let BrowserEventOutcome::Recorded(alert) = engine
        .record_browser_event(
            BrowserSecurityEventType::ClickFixPastejacking,
            "https://clickfix.example.invalid/verify",
            Some("mshta.exe https://clickfix.example.invalid/payload"),
            event_ts,
        )
        .expect("record browser alert")
    else {
        panic!("expected recorded browser alert");
    };
    assert_eq!(alert.source_layer, "LAYER_4_BROWSER");
    assert_eq!(alert.process_instance_id, None);
    assert_eq!(alert.status, AlertStatus::Pending);

    // Transition the processless LAYER_4_BROWSER alert to ExpiredSuspended via the same
    // timeout path used by the daemon's periodic sweep.
    let expired = store
        .expire_pending_alerts(event_ts + 60_001)
        .expect("expire pending alerts");
    assert_eq!(expired, 1);
    let stored_expired = store
        .get_alert(&alert.alert_id)
        .expect("get expired alert")
        .expect("expired alert exists");
    assert_eq!(stored_expired.status, AlertStatus::ExpiredSuspended);

    // AllowPermanent must still be rejected on an ExpiredSuspended processless LAYER_4_BROWSER alert.
    let perm_err = engine
        .resolve_alert_with_outcome(
            &alert.alert_id,
            AlertDecision::AllowPermanent {
                use_signer_if_available: false,
                allow_dest: None,
            },
        )
        .expect_err("AllowPermanent must be rejected for processless LAYER_4_BROWSER");
    assert!(
        !perm_err.is_empty(),
        "expected explanatory error message on AllowPermanent rejection"
    );
    assert_eq!(
        store
            .get_alert(&alert.alert_id)
            .expect("re-fetch alert")
            .expect("alert exists")
            .status,
        AlertStatus::ExpiredSuspended,
        "failed AllowPermanent must leave ExpiredSuspended status unchanged"
    );

    // Resolve via live Named Pipe IPC (`IpcRequest::ResolveAlert`) with `AlertDecision::AllowOnce`.
    let ipc_handle = start_ipc_server(Arc::clone(&engine)).expect("start IPC server");
    let pipe_for_req = pipe_name.clone();
    let alert_id_for_req = alert.alert_id.clone();
    let ipc_resp = tokio::task::spawn_blocking(move || {
        send_pipe_request(
            &pipe_for_req,
            &IpcRequest::ResolveAlert {
                alert_id: alert_id_for_req,
                decision: AlertDecision::AllowOnce,
            },
        )
    })
    .await
    .expect("IPC request join");
    match ipc_resp {
        IpcResponse::Ack { message } => {
            assert!(
                message.contains("APPROVED_ONCE"),
                "expected APPROVED_ONCE in Ack message, got: {message}"
            );
            assert!(
                !message.contains("rule "),
                "AllowOnce on processless LAYER_4_BROWSER must not save a rule: {message}"
            );
        }
        other => panic!("expected IpcResponse::Ack, got {other:?}"),
    }

    let resolved = store
        .get_alert(&alert.alert_id)
        .expect("get resolved alert")
        .expect("resolved alert exists");
    assert_eq!(resolved.status, AlertStatus::ApprovedOnce);
    assert!(resolved.resolved_at_ms.is_some());
    assert!(
        store.list_rules(None).expect("list rules").is_empty(),
        "AllowOnce must not create any saved rule"
    );
    assert!(defense.added_wfp().is_empty());
    assert!(defense.suspends().is_empty());

    // Verify a second ExpiredSuspended browser alert resolves cleanly via direct
    // `resolve_alert_with_outcome` as well, confirming `saved_rule_id == None`.
    let BrowserEventOutcome::Recorded(alert2) = engine
        .record_browser_event(
            BrowserSecurityEventType::HomographWarning,
            "https://paypa1.example.invalid/",
            None,
            event_ts + 100,
        )
        .expect("record second browser alert")
    else {
        panic!("expected recorded second browser alert");
    };
    assert_eq!(
        store
            .expire_pending_alerts(event_ts + 60_200)
            .expect("expire second alert"),
        1
    );
    let outcome = engine
        .resolve_alert_with_outcome(&alert2.alert_id, AlertDecision::AllowOnce)
        .expect("AllowOnce resolves ExpiredSuspended LAYER_4_BROWSER");
    assert_eq!(outcome.alert.status, AlertStatus::ApprovedOnce);
    assert!(outcome.alert.resolved_at_ms.is_some());
    assert_eq!(outcome.saved_rule_id, None);

    ipc_handle.shutdown().await;
    engine.shutdown_and_flush().await.expect("shutdown engine");
}

#[tokio::test]
async fn daemon_fu_p4_03_01_package_attrs_flow_to_store_and_sigma_canary_outbound_alerts() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockDefense::new());
    let notifier = Arc::new(RecordingNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let bth_exe = r"C:\Windows\System32\backgroundTaskHost.exe";
    let broker_exe = r"C:\Windows\System32\RuntimeBroker.exe";
    let font_exe = r"C:\Windows\System32\fontdrvhost.exe";
    for exe in [bth_exe, broker_exe, font_exe] {
        inspector.insert(
            exe,
            BinaryIdentity {
                exe_path: exe.to_string(),
                sha256: Some("a".repeat(64)),
                authenticode: None,
            },
        );
    }

    let sigma_rule = SigmaRule {
        id: "TEST-FU-P4-03-SIGMA".to_string(),
        title: "Suspicious BackgroundTaskHost ServerName".to_string(),
        severity: AlertSeverity::Medium,
        description: None,
        conditions: vec![
            FieldCondition {
                field: SigmaField::Image,
                modifier: MatchModifier::EndsWith,
                values: vec![r"\backgroundTaskHost.exe".to_string()],
            },
            FieldCondition {
                field: SigmaField::CommandLine,
                modifier: MatchModifier::Contains,
                values: vec!["-ServerName:Contoso.EvilTask".to_string()],
            },
        ],
    };

    let engine = DaemonEngine::start_with_all_dependencies(
        store.clone(),
        SigmaEngine::from_rules(vec![sigma_rule]).expect("compile sigma rule"),
        EarlyPruner::from_json_str("{}").expect("empty pruner"),
        DaemonConfig {
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::Audit,
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::clone(&notifier) as Arc<dyn NotificationDispatcher>,
        Arc::clone(&inspector) as Arc<dyn BinaryInspector>,
        Arc::new(NullLiveProcessInspector),
    );

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
    let id_both = ProcessIdentity::new(41_001, unix_ms_to_filetime(now_ms - 5_000));
    let id_pfn_only = ProcessIdentity::new(41_002, unix_ms_to_filetime(now_ms - 4_000));
    let id_sid_only = ProcessIdentity::new(41_003, unix_ms_to_filetime(now_ms - 3_000));

    // Seed PFN_ONLY_NON_APPCONTAINER and TOKEN_SID_ONLY via `seed_processes_with_package`.
    let seeded = engine
        .seed_processes_with_package(vec![
            CapturedProcessSnapshot {
                event: SensorEvent::ProcessStart {
                    identity: id_pfn_only,
                    parent_pid: 4,
                    exe_path: broker_exe.to_string(),
                    command_line: "RuntimeBroker.exe -Embedding".to_string(),
                    user_sid: None,
                },
                package: ProcessPackageInfo {
                    package_family_name: Some("Microsoft.Windows.Shell_cw5n1h2txyewy".to_string()),
                    package_sid: None,
                },
            },
            CapturedProcessSnapshot {
                event: SensorEvent::ProcessStart {
                    identity: id_sid_only,
                    parent_pid: 4,
                    exe_path: font_exe.to_string(),
                    command_line: "fontdrvhost.exe".to_string(),
                    user_sid: None,
                },
                package: ProcessPackageInfo {
                    package_family_name: None,
                    package_sid: Some("S-1-15-2-99-88-77".to_string()),
                },
            },
        ])
        .expect("seed_processes_with_package");
    assert_eq!(seeded, 2);

    // Send PFN+SID ProcessStart through the TwoLaneSender package-aware path.
    let sender = engine.sender();
    sender
        .send_with_package(
            SensorEvent::ProcessStart {
                identity: id_both,
                parent_pid: 4,
                exe_path: bth_exe.to_string(),
                command_line: "backgroundTaskHost.exe -ServerName:Contoso.EvilTask".to_string(),
                user_sid: None,
            },
            ProcessPackageInfo {
                package_family_name: Some("Contoso.EvilTask_12345".to_string()),
                package_sid: Some("S-1-15-2-10-20-30".to_string()),
            },
        )
        .await
        .expect("send_with_package ProcessStart");

    // Emit Canary and NetworkConnect events for `id_both` (no `NEVER_SUSPEND` exemption on backgroundTaskHost.exe).
    sender
        .send(SensorEvent::CanaryFileAccess {
            pid: id_both.pid,
            target_path: r"C:\Users\Alice\.env.prod".to_string(),
            category: CanaryCategory::EnvFile,
            access_mask: 0x2,
            is_write_or_delete: true,
            timestamp_ms: now_ms - 1_000,
        })
        .await
        .expect("send CanaryFileAccess");
    sender
        .send_high_priority(SensorEvent::NetworkConnect {
            pid: id_both.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            dst_port: 443,
            domain_hint: Some("evil.example.invalid".to_string()),
            timestamp_ms: now_ms - 500,
        })
        .await
        .expect("send NetworkConnect");

    wait_high_priority_processed(&engine, 3, "ProcessStart + Canary + NetworkConnect").await;
    engine.shutdown_and_flush().await.expect("shutdown");

    // 1. Verify SQLite auxiliary columns preserve all 3 independent combinations and frozen ProcessRecord works.
    assert_eq!(
        store
            .get_process_package_info(&id_both.instance_id())
            .expect("get package both"),
        Some(ProcessPackageRecord {
            package_family_name: Some("Contoso.EvilTask_12345".to_string()),
            package_sid: Some("S-1-15-2-10-20-30".to_string()),
        })
    );
    assert_eq!(
        store
            .get_process_package_info(&id_pfn_only.instance_id())
            .expect("get package pfn only"),
        Some(ProcessPackageRecord {
            package_family_name: Some("Microsoft.Windows.Shell_cw5n1h2txyewy".to_string()),
            package_sid: None,
        })
    );
    assert_eq!(
        store
            .get_process_package_info(&id_sid_only.instance_id())
            .expect("get package sid only"),
        Some(ProcessPackageRecord {
            package_family_name: None,
            package_sid: Some("S-1-15-2-99-88-77".to_string()),
        })
    );
    let snap = store
        .query_flight_recorder(10, Some(&id_both.instance_id()))
        .expect("query_flight_recorder intact");
    assert_eq!(snap.processes.len(), 1);
    assert_eq!(snap.processes[0].exe_path, bth_exe);

    // 2. Verify all 3 alert layers (`LAYER_2_RULES`, `LAYER_1_CANARY`, `LAYER_3_NETWORK`) carry package attrs.
    let alerts = store.list_alerts(None, 20).expect("list alerts");
    for layer in ["LAYER_2_RULES", "LAYER_1_CANARY", "LAYER_3_NETWORK"] {
        let alert = alerts
            .iter()
            .find(|a| a.source_layer == layer)
            .unwrap_or_else(|| panic!("expected alert from {layer}, got {alerts:?}"));
        let ctx: serde_json::Value =
            serde_json::from_str(&alert.context_json).expect("parse alert context_json");
        assert_eq!(
            ctx.get("package_family_name").and_then(|v| v.as_str()),
            Some("Contoso.EvilTask_12345"),
            "missing package_family_name in {layer}"
        );
        assert_eq!(
            ctx.get("package_sid").and_then(|v| v.as_str()),
            Some("S-1-15-2-10-20-30"),
            "missing package_sid in {layer}"
        );
    }
}

#[tokio::test]
async fn daemon_fu_p4_03_02_single_candidate_wfp_drop_prefers_event_sid_and_falls_back_to_table() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockDefense::new());
    let inspector = Arc::new(MapBinaryInspector::default());

    let app_a = r"C:\Tools\pkg_drop_a.exe";
    let app_b = r"C:\Tools\pkg_drop_b.exe";
    let app_c = r"C:\Tools\pkg_drop_c.exe";
    for exe in [app_a, app_b, app_c] {
        inspector.insert(
            exe,
            BinaryIdentity {
                exe_path: exe.to_string(),
                sha256: Some("b".repeat(64)),
                authenticode: None,
            },
        );
    }

    let engine = DaemonEngine::start_with_all_dependencies(
        store.clone(),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::Audit,
            wfp_drop_dns_grace_ms: 0,
            wfp_drop_attribution_grace_ms: 0,
            wfp_drop_live_sibling_os_check: false,
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(RecordingNotifier::default()),
        Arc::clone(&inspector) as Arc<dyn BinaryInspector>,
        Arc::new(NullLiveProcessInspector),
    );

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
    let id_a = ProcessIdentity::new(42_001, unix_ms_to_filetime(now_ms - 5_000));
    let id_b = ProcessIdentity::new(42_002, unix_ms_to_filetime(now_ms - 5_000));
    let id_c = ProcessIdentity::new(42_003, unix_ms_to_filetime(now_ms - 5_000));
    let sender = engine.sender();

    sender
        .send_with_package(
            SensorEvent::ProcessStart {
                identity: id_a,
                parent_pid: 4,
                exe_path: app_a.to_string(),
                command_line: "pkg_drop_a.exe".to_string(),
                user_sid: None,
            },
            ProcessPackageInfo {
                package_family_name: Some("Contoso.DropA_1".to_string()),
                package_sid: Some("S-1-15-2-table-a".to_string()),
            },
        )
        .await
        .expect("send start A");
    sender
        .send_with_package(
            SensorEvent::ProcessStart {
                identity: id_b,
                parent_pid: 4,
                exe_path: app_b.to_string(),
                command_line: "pkg_drop_b.exe".to_string(),
                user_sid: None,
            },
            ProcessPackageInfo {
                package_family_name: Some("Contoso.DropB_2".to_string()),
                package_sid: Some("S-1-15-2-table-fallback-b".to_string()),
            },
        )
        .await
        .expect("send start B");
    sender
        .send_with_package(
            SensorEvent::ProcessStart {
                identity: id_c,
                parent_pid: 4,
                exe_path: app_c.to_string(),
                command_line: "pkg_drop_c.exe".to_string(),
                user_sid: None,
            },
            ProcessPackageInfo {
                package_family_name: Some("Contoso.DropC_3".to_string()),
                package_sid: Some("S-1-15-2-match-c".to_string()),
            },
        )
        .await
        .expect("send start C");
    wait_high_priority_processed(&engine, 3, "three ProcessStarts").await;

    // A: Mismatched WFP drop event SID refuses cross-package attribution (PRG-001): routes to
    //    ambiguous app-level handling without adopting candidate PFN or suspending `id_a`.
    assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
        os_filter_id: 501,
        rule_handle: 501,
        exe_path: app_a.to_string(),
        protocol: 6,
        dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 11)),
        dst_port: 443,
        timestamp_ms: now_ms,
        package_sid: Some("S-1-15-2-wfp-override-a".to_string()),
    }));

    // B: WFP drop event has package_sid == None -> falls back to table TokenAppContainerSid and PFN.
    assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
        os_filter_id: 502,
        rule_handle: 502,
        exe_path: app_b.to_string(),
        protocol: 6,
        dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 12)),
        dst_port: 443,
        timestamp_ms: now_ms,
        package_sid: None,
    }));

    // C: Case-insensitive matching SID preserves both candidate PFN and event SID.
    assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
        os_filter_id: 503,
        rule_handle: 503,
        exe_path: app_c.to_string(),
        protocol: 6,
        dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 13)),
        dst_port: 443,
        timestamp_ms: now_ms,
        package_sid: Some("s-1-15-2-match-c".to_string()),
    }));

    let deadline = Instant::now() + Duration::from_secs(2);
    while store.list_alerts(None, 10).expect("list").len() < 3 {
        assert!(Instant::now() < deadline, "timed out waiting for three WFP drop alerts");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    engine.shutdown_and_flush().await.expect("shutdown");

    let alerts = store.list_alerts(None, 10).expect("list alerts");
    let alert_a = alerts
        .iter()
        .find(|a| {
            serde_json::from_str::<serde_json::Value>(&a.context_json)
                .ok()
                .and_then(|v| v.get("dst_ip").and_then(|d| d.as_str()).map(str::to_owned))
                .as_deref()
                == Some("198.51.100.11")
        })
        .expect("alert A");
    assert_eq!(
        alert_a.process_instance_id, None,
        "PRG-001: SID-mismatched drop must not attribute to candidate process"
    );
    assert!(
        !defense.suspends().contains(&id_a),
        "PRG-001: SID-mismatched drop must not suspend mismatched candidate"
    );
    let ctx_a: serde_json::Value = serde_json::from_str(&alert_a.context_json).expect("ctx A");
    assert_eq!(ctx_a["attribution"], "app_level_ambiguous");
    assert!(
        ctx_a["package_family_name"].is_null(),
        "mismatched WFP package_sid must clear candidate package_family_name, got {ctx_a}"
    );
    assert_eq!(ctx_a["package_sid"], "S-1-15-2-wfp-override-a");

    let alert_b = alerts
        .iter()
        .find(|a| a.process_instance_id.as_deref() == Some(id_b.instance_id().as_str()))
        .expect("alert B");
    let ctx_b: serde_json::Value = serde_json::from_str(&alert_b.context_json).expect("ctx B");
    assert_eq!(ctx_b["package_family_name"], "Contoso.DropB_2");
    assert_eq!(ctx_b["package_sid"], "S-1-15-2-table-fallback-b");

    let alert_c = alerts
        .iter()
        .find(|a| a.process_instance_id.as_deref() == Some(id_c.instance_id().as_str()))
        .expect("alert C");
    let ctx_c: serde_json::Value = serde_json::from_str(&alert_c.context_json).expect("ctx C");
    assert_eq!(ctx_c["package_family_name"], "Contoso.DropC_3");
    assert_eq!(ctx_c["package_sid"], "s-1-15-2-match-c");
}

#[tokio::test]
async fn daemon_fu_p4_03_03_ambiguous_wfp_drop_disambiguates_package_by_sid_without_guessing() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockDefense::new());
    let inspector = Arc::new(MapBinaryInspector::default());

    let bth_exe = r"C:\Windows\System32\backgroundTaskHost.exe";
    inspector.insert(
        bth_exe,
        BinaryIdentity {
            exe_path: bth_exe.to_string(),
            sha256: Some("c".repeat(64)),
            authenticode: None,
        },
    );

    let engine = DaemonEngine::start_with_all_dependencies(
        store.clone(),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::Audit,
            wfp_drop_dns_grace_ms: 0,
            wfp_drop_attribution_grace_ms: 0,
            wfp_drop_live_sibling_os_check: false,
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(RecordingNotifier::default()),
        Arc::clone(&inspector) as Arc<dyn BinaryInspector>,
        Arc::new(NullLiveProcessInspector),
    );

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
    let id1 = ProcessIdentity::new(43_001, unix_ms_to_filetime(now_ms - 5_000));
    let id2 = ProcessIdentity::new(43_002, unix_ms_to_filetime(now_ms - 4_500));
    let sender = engine.sender();

    sender
        .send_with_package(
            SensorEvent::ProcessStart {
                identity: id1,
                parent_pid: 4,
                exe_path: bth_exe.to_string(),
                command_line: "backgroundTaskHost.exe -ServerName:PkgA".to_string(),
                user_sid: None,
            },
            ProcessPackageInfo {
                package_family_name: Some("PkgA_111".to_string()),
                package_sid: Some("S-1-15-2-111".to_string()),
            },
        )
        .await
        .expect("send id1");
    sender
        .send_with_package(
            SensorEvent::ProcessStart {
                identity: id2,
                parent_pid: 4,
                exe_path: bth_exe.to_string(),
                command_line: "backgroundTaskHost.exe -ServerName:PkgB".to_string(),
                user_sid: None,
            },
            ProcessPackageInfo {
                package_family_name: Some("PkgB_222".to_string()),
                package_sid: Some("S-1-15-2-222".to_string()),
            },
        )
        .await
        .expect("send id2");
    wait_high_priority_processed(&engine, 2, "two backgroundTaskHost instances").await;

    let shared_dst = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 44));
    // 1. Ambiguous drop with `S-1-15-2-111` resolves `PkgA_111` in context_json.
    assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
        os_filter_id: 601,
        rule_handle: 601,
        exe_path: bth_exe.to_string(),
        protocol: 6,
        dst_ip: shared_dst,
        dst_port: 443,
        timestamp_ms: now_ms,
        package_sid: Some("S-1-15-2-111".to_string()),
    }));

    // 2. Simultaneous drop within 250ms to the SAME IP/port from `S-1-15-2-222` must NOT be
    //    suppressed by `WfpDropDedupCache`.
    assert!(
        engine.ingest_wfp_drop_event(WfpDropEvent {
            os_filter_id: 602,
            rule_handle: 602,
            exe_path: bth_exe.to_string(),
            protocol: 6,
            dst_ip: shared_dst,
            dst_port: 443,
            timestamp_ms: now_ms + 50,
            package_sid: Some("S-1-15-2-222".to_string()),
        }),
        "distinct package_sid drops within 250ms must not suppress each other"
    );

    // 3. Ambiguous drop on a different IP with `package_sid == None` across two distinct packages
    //    must keep both `package_family_name` and `package_sid` as `null` rather than guessing.
    let no_sid_dst = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 45));
    assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
        os_filter_id: 603,
        rule_handle: 603,
        exe_path: bth_exe.to_string(),
        protocol: 6,
        dst_ip: no_sid_dst,
        dst_port: 443,
        timestamp_ms: now_ms + 100,
        package_sid: None,
    }));

    let deadline = Instant::now() + Duration::from_secs(2);
    while store.list_alerts(None, 10).expect("list").len() < 3 {
        assert!(Instant::now() < deadline, "timed out waiting for ambiguous drop alerts");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    engine.shutdown_and_flush().await.expect("shutdown");

    let alerts = store.list_alerts(None, 10).expect("list alerts");
    let shared_alerts: Vec<serde_json::Value> = alerts
        .iter()
        .filter_map(|a| serde_json::from_str::<serde_json::Value>(&a.context_json).ok())
        .filter(|ctx| ctx.get("dst_ip").and_then(|d| d.as_str()) == Some("198.51.100.44"))
        .collect();
    assert_eq!(
        shared_alerts.len(),
        2,
        "distinct package_sid drops on shared IP must emit two alerts, got {shared_alerts:?}"
    );
    let alert_a = shared_alerts
        .iter()
        .find(|ctx| ctx.get("package_sid").and_then(|s| s.as_str()) == Some("S-1-15-2-111"))
        .expect("alert for PkgA_111");
    assert_eq!(alert_a["attribution"], "app_level_ambiguous");
    assert_eq!(alert_a["package_family_name"], "PkgA_111");
    assert_eq!(alert_a["package_sid"], "S-1-15-2-111");

    let alert_b = shared_alerts
        .iter()
        .find(|ctx| ctx.get("package_sid").and_then(|s| s.as_str()) == Some("S-1-15-2-222"))
        .expect("alert for PkgB_222");
    assert_eq!(alert_b["attribution"], "app_level_ambiguous");
    assert_eq!(alert_b["package_family_name"], "PkgB_222");
    assert_eq!(alert_b["package_sid"], "S-1-15-2-222");

    let unguessed_alert = alerts
        .iter()
        .find(|a| {
            serde_json::from_str::<serde_json::Value>(&a.context_json)
                .ok()
                .and_then(|v| v.get("dst_ip").and_then(|d| d.as_str()).map(str::to_owned))
                .as_deref()
                == Some("198.51.100.45")
        })
        .expect("alert for no_sid_dst");
    let unguessed_ctx: serde_json::Value =
        serde_json::from_str(&unguessed_alert.context_json).expect("unguessed ctx");
    assert_eq!(unguessed_ctx["attribution"], "app_level_ambiguous");
    assert!(unguessed_ctx["package_family_name"].is_null());
    assert!(unguessed_ctx["package_sid"].is_null());
}

#[tokio::test]
async fn daemon_fu_p4_03_04_canary_backfill_populates_package_attrs_in_store_and_alert() {
    struct SingleLiveInspector {
        pid: u32,
        info: LiveProcessInfo,
    }
    impl LiveProcessInspector for SingleLiveInspector {
        fn inspect_live_process(&self, pid: u32) -> Option<LiveProcessInfo> {
            (pid == self.pid).then(|| self.info.clone())
        }
    }

    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockDefense::new());
    let inspector = Arc::new(MapBinaryInspector::default());
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
    let created_100ns = unix_ms_to_filetime(now_ms - 5_000);
    let pid = 44_004u32;
    let exe = r"C:\Windows\System32\backgroundTaskHost.exe";
    inspector.insert(
        exe,
        BinaryIdentity {
            exe_path: exe.to_string(),
            sha256: Some("d".repeat(64)),
            authenticode: None,
        },
    );

    let live_inspector = Arc::new(SingleLiveInspector {
        pid,
        info: LiveProcessInfo {
            create_time_100ns: created_100ns,
            exe_path: Some(exe.to_string()),
            command_line: Some("backgroundTaskHost.exe -ServerName:CanaryApp".to_string()),
            package_family_name: Some("Canary.App_abcde".to_string()),
            package_sid: Some("S-1-15-2-44-55-66".to_string()),
        },
    });

    let engine = DaemonEngine::start_with_all_dependencies(
        store.clone(),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            outbound_firewall_enabled: false,
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(RecordingNotifier::default()),
        Arc::clone(&inspector) as Arc<dyn BinaryInspector>,
        live_inspector,
    );

    engine
        .sender()
        .send(SensorEvent::CanaryFileAccess {
            pid,
            target_path: r"C:\Users\Alice\.ssh\id_rsa".to_string(),
            category: CanaryCategory::SshKey,
            access_mask: 0x1,
            is_write_or_delete: false,
            timestamp_ms: now_ms,
        })
        .await
        .expect("send canary before ProcessStart");
    wait_high_priority_processed(&engine, 1, "CanaryFileAccess backfill").await;
    engine.shutdown_and_flush().await.expect("shutdown");

    let expected_inst_id = ProcessIdentity::new(pid, created_100ns).instance_id();
    assert_eq!(
        store
            .get_process_package_info(&expected_inst_id)
            .expect("get backfilled package attrs"),
        Some(ProcessPackageRecord {
            package_family_name: Some("Canary.App_abcde".to_string()),
            package_sid: Some("S-1-15-2-44-55-66".to_string()),
        })
    );

    let alerts = store.list_alerts(None, 10).expect("list alerts");
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].source_layer, "LAYER_1_CANARY");
    assert_eq!(
        alerts[0].process_instance_id.as_deref(),
        Some(expected_inst_id.as_str())
    );
    let ctx: serde_json::Value =
        serde_json::from_str(&alerts[0].context_json).expect("parse canary context");
    assert_eq!(ctx["package_family_name"], "Canary.App_abcde");
    assert_eq!(ctx["package_sid"], "S-1-15-2-44-55-66");
}

#[tokio::test]
async fn daemon_fu_p4_03_05_process_stop_sigma_alert_preserves_package_attrs() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockDefense::new());
    let inspector = Arc::new(MapBinaryInspector::default());

    let bth_exe = r"C:\Windows\System32\backgroundTaskHost.exe";
    inspector.insert(
        bth_exe,
        BinaryIdentity {
            exe_path: bth_exe.to_string(),
            sha256: Some("e".repeat(64)),
            authenticode: None,
        },
    );

    let sigma_rule = SigmaRule {
        id: "TEST-FU-P4-03-STOP".to_string(),
        title: "BackgroundTaskHost Image Exit Rule".to_string(),
        severity: AlertSeverity::Medium,
        description: None,
        conditions: vec![FieldCondition {
            field: SigmaField::Image,
            modifier: MatchModifier::EndsWith,
            values: vec![r"\backgroundTaskHost.exe".to_string()],
        }],
    };

    let engine = DaemonEngine::start_with_all_dependencies(
        store.clone(),
        SigmaEngine::from_rules(vec![sigma_rule]).expect("compile sigma rule"),
        EarlyPruner::default(),
        DaemonConfig {
            outbound_firewall_enabled: false,
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(RecordingNotifier::default()),
        Arc::clone(&inspector) as Arc<dyn BinaryInspector>,
        Arc::new(NullLiveProcessInspector),
    );

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
    let pid = 45_005u32;
    let id = ProcessIdentity::new(pid, unix_ms_to_filetime(now_ms - 2_000));
    let sender = engine.sender();

    // `EarlyPruner::default()` suppresses Sigma evaluation on `ProcessStart` for
    // `backgroundTaskHost.exe`, leaving `ProcessStop` as the first rule match.
    sender
        .send_with_package(
            SensorEvent::ProcessStart {
                identity: id,
                parent_pid: 4,
                exe_path: bth_exe.to_string(),
                command_line: "backgroundTaskHost.exe -ServerName:Contoso.StopHost".to_string(),
                user_sid: None,
            },
            ProcessPackageInfo {
                package_family_name: Some("Contoso.StopHost_1".to_string()),
                package_sid: Some("S-1-15-2-stop-1".to_string()),
            },
        )
        .await
        .expect("send start");
    wait_high_priority_processed(&engine, 1, "ProcessStart before stop").await;

    sender
        .send(SensorEvent::ProcessStop {
            pid,
            exit_code: 0,
            exit_time_100ns: unix_ms_to_filetime(now_ms),
        })
        .await
        .expect("send stop");
    wait_high_priority_processed(&engine, 2, "ProcessStop").await;
    engine.shutdown_and_flush().await.expect("shutdown");

    let alerts = store.list_alerts(None, 10).expect("list alerts");
    assert_eq!(alerts.len(), 1, "ProcessStop should fire the Sigma Image rule once");
    assert_eq!(alerts[0].source_layer, "LAYER_2_RULES");
    assert_eq!(alerts[0].rule_id, "TEST-FU-P4-03-STOP");
    assert_eq!(
        alerts[0].process_instance_id.as_deref(),
        Some(id.instance_id().as_str())
    );
    let ctx: serde_json::Value =
        serde_json::from_str(&alerts[0].context_json).expect("parse stop alert context");
    assert_eq!(ctx["package_family_name"], "Contoso.StopHost_1");
    assert_eq!(ctx["package_sid"], "S-1-15-2-stop-1");
}

#[tokio::test]
async fn daemon_fu_p4_03_b2_cross_package_isolation_and_legacy_list_isolation() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockDefense::new());
    let inspector = Arc::new(MapBinaryInspector::default());

    let bth_exe = r"C:\Windows\System32\backgroundTaskHost.exe";
    let signer = "CN=Microsoft Windows";
    let root_tp = "ab".repeat(20);
    inspector.insert(
        bth_exe,
        BinaryIdentity {
            exe_path: bth_exe.to_string(),
            sha256: Some("f".repeat(64)),
            authenticode: Some(AuthenticodeInfo {
                signer_subject: signer.to_string(),
                root_thumbprint: root_tp.clone(),
            }),
        },
    );

    let pipe_name = unique_test_pipe_name();
    let engine = DaemonEngine::start_with_all_dependencies(
        store.clone(),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::Enforce,
            dev_mode_bypass_ui_auth: true,
            pipe_name: pipe_name.clone(),
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(RecordingNotifier::default()),
        Arc::clone(&inspector) as Arc<dyn BinaryInspector>,
        Arc::new(NullLiveProcessInspector),
    );
    let ipc_handle = start_ipc_server(Arc::clone(&engine)).expect("start ipc");

    let sid_a = "S-1-15-2-1001-1";
    let pfn_a = "Contoso.PkgA_8wekyb3d8bbwe";
    let sid_b = "S-1-15-2-2002-1";
    let pfn_b = "Contoso.PkgB_8wekyb3d8bbwe";

    let scoped_allow_a = ScopedPolicyRuleRecord {
        rule_id: "SC-ALLOW-BTH-A".to_string(),
        scope: RuleScope::NetworkAllow,
        exe_path_pattern: bth_exe.to_string(),
        sha256: None,
        signer_subject: Some(signer.to_string()),
        root_thumbprint: Some(root_tp),
        allowed_target: None,
        package_family_name: Some(pfn_a.to_string()),
        package_sid: Some(sid_a.to_string()),
        command_line_pattern: None,
        created_at_ms: 1_750_000_000_000,
        created_by: "test_b2".to_string(),
    };
    let pipe = pipe_name.clone();
    let rule_clone = scoped_allow_a.clone();
    let upsert_resp = tokio::task::spawn_blocking(move || {
        send_pipe_request(&pipe, &IpcRequest::UpsertScopedRule { rule: rule_clone })
    })
    .await
    .expect("join upsert");
    assert!(matches!(upsert_resp, IpcResponse::Ack { .. }), "got {upsert_resp:?}");

    // Legacy ListRules must remain completely isolated from scoped_policy_rules.
    let pipe = pipe_name.clone();
    let legacy_resp = tokio::task::spawn_blocking(move || {
        send_pipe_request(&pipe, &IpcRequest::ListRules { scope: None })
    })
    .await
    .expect("join ListRules");
    match legacy_resp {
        IpcResponse::Rules(rules) => assert!(rules.is_empty(), "legacy ListRules leaked scoped rules"),
        other => panic!("unexpected ListRules response: {other:?}"),
    }
    assert!(store.list_rules(None).expect("store list_rules").is_empty());

    let pipe = pipe_name.clone();
    let scoped_resp = tokio::task::spawn_blocking(move || {
        send_pipe_request(&pipe, &IpcRequest::ListScopedRules { scope: None })
    })
    .await
    .expect("join ListScopedRules");
    match scoped_resp {
        IpcResponse::ScopedRules(rules) => {
            assert_eq!(rules.len(), 1);
            assert_eq!(rules[0].rule_id, "SC-ALLOW-BTH-A");
        }
        other => panic!("unexpected ListScopedRules response: {other:?}"),
    }

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
    let id_a = ProcessIdentity::new(47_101, unix_ms_to_filetime(now_ms - 1_000));
    let id_b = ProcessIdentity::new(47_102, unix_ms_to_filetime(now_ms - 900));
    let sender = engine.sender();

    sender
        .send_with_package(
            SensorEvent::ProcessStart {
                identity: id_a,
                parent_pid: 4,
                exe_path: bth_exe.to_string(),
                command_line: "backgroundTaskHost.exe -ServerName:PkgA".to_string(),
                user_sid: None,
            },
            ProcessPackageInfo {
                package_family_name: Some(pfn_a.to_string()),
                package_sid: Some(sid_a.to_string()),
            },
        )
        .await
        .expect("send start A");
    sender
        .send_with_package(
            SensorEvent::ProcessStart {
                identity: id_b,
                parent_pid: 4,
                exe_path: bth_exe.to_string(),
                command_line: "backgroundTaskHost.exe -ServerName:PkgB".to_string(),
                user_sid: None,
            },
            ProcessPackageInfo {
                package_family_name: Some(pfn_b.to_string()),
                package_sid: Some(sid_b.to_string()),
            },
        )
        .await
        .expect("send start B");
    wait_high_priority_processed(&engine, 2, "two backgroundTaskHost starts").await;

    let scoped_wfp = defense.added_scoped_wfp();
    assert!(
        scoped_wfp.iter().any(|c| {
            c.package_sid.as_deref() == Some(sid_a) && c.remote_ip.is_none() && c.allow
        }),
        "expected package-scoped WFP Permit for Package A, got {scoped_wfp:?}"
    );
    assert!(
        !scoped_wfp.iter().any(|c| c.package_sid.as_deref() == Some(sid_b)),
        "Package B must NOT receive a scoped WFP Permit, got {scoped_wfp:?}"
    );
    assert!(
        !defense.added_wfp().iter().any(|c| {
            c.allow && c.exe_path.eq_ignore_ascii_case(bth_exe)
        }),
        "scoped NetworkAllow must NEVER install an unscoped host-wide Permit"
    );

    // Outbound connect from Package A is allowed silently; Package B triggers an alert (no cache leak).
    sender
        .send_high_priority(SensorEvent::NetworkConnect {
            pid: id_a.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms,
        })
        .await
        .expect("send net A");
    sender
        .send_high_priority(SensorEvent::NetworkConnect {
            pid: id_b.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 78)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms,
        })
        .await
        .expect("send net B");
    wait_high_priority_processed(&engine, 4, "two NetworkConnect events").await;
    ipc_handle.shutdown().await;
    engine.shutdown_and_flush().await.expect("shutdown");

    let alerts = store.list_alerts(None, 20).expect("list alerts");
    assert_eq!(alerts.len(), 1, "expected only Package B outbound alert, got {alerts:?}");
    assert_eq!(
        alerts[0].process_instance_id.as_deref(),
        Some(id_b.instance_id().as_str())
    );
    let ctx_b: serde_json::Value = serde_json::from_str(&alerts[0].context_json).expect("ctx B");
    assert_eq!(ctx_b["package_sid"], sid_b);
    assert_eq!(ctx_b["package_family_name"], pfn_b);
}

#[tokio::test]
async fn daemon_fu_p4_03_b2_compensatory_rollback_on_wfp_sync_failure() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockDefense::new());
    let inspector = Arc::new(MapBinaryInspector::default());

    let bth_exe = r"C:\Windows\System32\backgroundTaskHost.exe";
    let signer = "CN=Microsoft Windows";
    let root_tp = "cd".repeat(20);
    inspector.insert(
        bth_exe,
        BinaryIdentity {
            exe_path: bth_exe.to_string(),
            sha256: Some("e".repeat(64)),
            authenticode: Some(AuthenticodeInfo {
                signer_subject: signer.to_string(),
                root_thumbprint: root_tp.clone(),
            }),
        },
    );

    let engine = DaemonEngine::start_with_all_dependencies(
        store.clone(),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::Enforce,
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(RecordingNotifier::default()),
        Arc::clone(&inspector) as Arc<dyn BinaryInspector>,
        Arc::new(NullLiveProcessInspector),
    );

    let sid_a = "S-1-15-2-2001-1";
    let pfn_a = "Contoso.RollbackA_8wekyb3d8bbwe";
    let sid_b = "S-1-15-2-2002-1";
    let pfn_b = "Contoso.RollbackB_8wekyb3d8bbwe";

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
    let id_b = ProcessIdentity::new(47_201, unix_ms_to_filetime(now_ms - 1_000));
    engine
        .sender()
        .send_with_package(
            SensorEvent::ProcessStart {
                identity: id_b,
                parent_pid: 4,
                exe_path: bth_exe.to_string(),
                command_line: "backgroundTaskHost.exe -ServerName:RollbackB".to_string(),
                user_sid: None,
            },
            ProcessPackageInfo {
                package_family_name: Some(pfn_b.to_string()),
                package_sid: Some(sid_b.to_string()),
            },
        )
        .await
        .expect("send start B");
    wait_high_priority_processed(&engine, 1, "start before rollback tests").await;

    let allow_a = ScopedPolicyRuleRecord {
        rule_id: "SC-RB-ALLOW-A".to_string(),
        scope: RuleScope::NetworkAllow,
        exe_path_pattern: bth_exe.to_string(),
        sha256: None,
        signer_subject: Some(signer.to_string()),
        root_thumbprint: Some(root_tp.clone()),
        allowed_target: None,
        package_family_name: Some(pfn_a.to_string()),
        package_sid: Some(sid_a.to_string()),
        command_line_pattern: None,
        created_at_ms: 1_750_000_000_000,
        created_by: "test_b2".to_string(),
    };
    let mut allow_b = allow_a.clone();
    allow_b.rule_id = "SC-RB-ALLOW-B".to_string();
    allow_b.package_family_name = Some(pfn_b.to_string());
    allow_b.package_sid = Some(sid_b.to_string());

    // 1. UpsertScopedRule failure rolls back SQLite and leaves zero orphaned WFP filters.
    defense.set_fail_next_scoped_add(true);
    let up_err = engine.upsert_scoped_policy_rule(&allow_b);
    assert!(up_err.is_err(), "expected upsert_scoped_policy_rule failure");
    assert!(
        store.list_scoped_rules(None).expect("list scoped").is_empty(),
        "failed upsert_scoped_policy_rule must roll back SQLite"
    );

    // 2. DeleteScopedRule remove failure restores the deleted scoped rule into SQLite.
    engine
        .upsert_scoped_policy_rule(&allow_b)
        .expect("upsert allow_b cleanly");
    assert_eq!(store.list_scoped_rules(None).expect("list").len(), 1);
    defense.set_fail_next_remove(true);
    let del_err = engine.delete_scoped_policy_rule(&allow_b.rule_id);
    assert!(del_err.is_err(), "expected delete_scoped_policy_rule failure");
    assert!(
        store
            .get_scoped_rule(&allow_b.rule_id)
            .expect("query restored")
            .is_some(),
        "failed delete_scoped_policy_rule must restore SQLite rule"
    );
    assert!(
        engine
            .delete_scoped_policy_rule(&allow_b.rule_id)
            .expect("clean delete allow_b")
            .0
    );

    // 3. ResolveAlertScoped (AllowPermanent & TerminateAndBlock) rollback on WFP add failure.
    let alert_id = "ALERT-SC-RB-01";
    let alert = AlertRecord {
        alert_id: alert_id.to_string(),
        timestamp_ms: now_ms,
        severity: AlertSeverity::Medium,
        source_layer: "LAYER_3_NETWORK".to_string(),
        rule_id: "NET_OUTBOUND_ENFORCE".to_string(),
        title: "Outbound".to_string(),
        process_instance_id: Some(id_b.instance_id()),
        process_suspended: false,
        status: AlertStatus::Pending,
        context_json: serde_json::json!({
            "exe_path": bth_exe,
            "signer_subject": signer,
            "root_thumbprint": root_tp,
            "package_family_name": pfn_b,
            "package_sid": sid_b,
            "dst_ip": "198.51.100.88",
            "dst_port": 443
        })
        .to_string(),
        resolved_at_ms: None,
    };
    store.record_alert(&alert).expect("record alert");

    defense.set_fail_next_scoped_add(true);
    let allow_err = engine.resolve_alert_scoped_with_outcome(
        alert_id,
        AlertDecision::AllowPermanent {
            use_signer_if_available: true,
            allow_dest: None,
        },
        true,
    );
    assert!(allow_err.is_err(), "expected ResolveAlertScoped AllowPermanent WFP failure");
    assert_eq!(
        store.get_alert(alert_id).expect("get").expect("exists").status,
        AlertStatus::Pending
    );
    assert!(store.list_scoped_rules(None).expect("list").is_empty());

    defense.set_fail_next_scoped_add(true);
    let blk_err = engine.resolve_alert_scoped_with_outcome(
        alert_id,
        AlertDecision::TerminateAndBlock {
            add_block_rule: true,
        },
        true,
    );
    assert!(blk_err.is_err(), "expected ResolveAlertScoped TerminateAndBlock WFP failure");
    assert_eq!(
        store.get_alert(alert_id).expect("get").expect("exists").status,
        AlertStatus::Pending
    );
    assert!(store.list_scoped_rules(None).expect("list").is_empty());

    engine.shutdown_and_flush().await.expect("shutdown");
}

#[tokio::test]
async fn daemon_fu_p4_03_b2_resolve_alert_scoped_terminate_and_allow_boundaries() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockDefense::new());
    let inspector = Arc::new(MapBinaryInspector::default());

    let bth_exe = r"C:\Windows\System32\backgroundTaskHost.exe";
    let pfn_only_exe = r"C:\Tools\pfn_only_host.exe";
    let unsigned_exe = r"C:\Tools\unsigned_b2.exe";
    let signer = "CN=Microsoft Windows";
    let root_tp = "ef".repeat(20);
    for signed in [bth_exe, pfn_only_exe] {
        inspector.insert(
            signed,
            BinaryIdentity {
                exe_path: signed.to_string(),
                sha256: Some("a".repeat(64)),
                authenticode: Some(AuthenticodeInfo {
                    signer_subject: signer.to_string(),
                    root_thumbprint: root_tp.clone(),
                }),
            },
        );
    }
    inspector.insert(
        unsigned_exe,
        BinaryIdentity {
            exe_path: unsigned_exe.to_string(),
            sha256: Some("b".repeat(64)),
            authenticode: None,
        },
    );

    let engine = DaemonEngine::start_with_all_dependencies(
        store.clone(),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::Enforce,
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(RecordingNotifier::default()),
        Arc::clone(&inspector) as Arc<dyn BinaryInspector>,
        Arc::new(NullLiveProcessInspector),
    );

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
    let id_ac = ProcessIdentity::new(47_301, unix_ms_to_filetime(now_ms - 3_000));
    let id_rb = ProcessIdentity::new(47_302, unix_ms_to_filetime(now_ms - 2_000));
    let id_nonpkg = ProcessIdentity::new(47_303, unix_ms_to_filetime(now_ms - 1_000));
    let sid_ac = "S-1-15-2-3001-1";
    let pfn_ac = "Contoso.AcPkg_8wekyb3d8bbwe";
    let sender = engine.sender();

    // Case A: AppContainer process emits NetworkConnect -> transient host block installed ->
    // TerminateAndBlock(scope_to_package=true) saves scoped block, adds scoped WFP block,
    // AND releases the host-wide TransientContainment block on backgroundTaskHost.exe.
    sender
        .send_with_package(
            SensorEvent::ProcessStart {
                identity: id_ac,
                parent_pid: 4,
                exe_path: bth_exe.to_string(),
                command_line: "backgroundTaskHost.exe -ServerName:AcPkg".to_string(),
                user_sid: None,
            },
            ProcessPackageInfo {
                package_family_name: Some(pfn_ac.to_string()),
                package_sid: Some(sid_ac.to_string()),
            },
        )
        .await
        .expect("send start AC");
    sender
        .send_high_priority(SensorEvent::NetworkConnect {
            pid: id_ac.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 91)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms,
        })
        .await
        .expect("send net AC");
    wait_high_priority_processed(&engine, 2, "AC outbound alert").await;

    let transient_bth_handle = defense
        .added_wfp()
        .iter()
        .find(|c| c.exe_path.eq_ignore_ascii_case(bth_exe) && !c.allow && c.remote_ip.is_none())
        .expect("transient host-wide containment handle on backgroundTaskHost.exe")
        .handle;
    let alert_ac = store
        .list_alerts(Some(AlertStatus::Pending), 10)
        .expect("list alerts")
        .into_iter()
        .find(|a| a.process_instance_id.as_deref() == Some(id_ac.instance_id().as_str()))
        .expect("alert_ac");

    let out_ac = engine
        .resolve_alert_scoped_with_outcome(
            &alert_ac.alert_id,
            AlertDecision::TerminateAndBlock {
                add_block_rule: true,
            },
            true,
        )
        .expect("resolve alert_ac");
    assert!(out_ac.saved_rule_id.is_some());
    assert!(defense.terminates().contains(&id_ac));
    assert!(
        defense.added_scoped_wfp().iter().any(|c| {
            c.package_sid.as_deref() == Some(sid_ac) && !c.allow && c.remote_ip.is_none()
        }),
        "expected package-scoped WFP block for {sid_ac}"
    );
    assert!(
        defense.removed_wfp().contains(&transient_bth_handle),
        "host-wide TransientContainment on backgroundTaskHost.exe must be released after installing package-scoped block"
    );
    assert!(store.list_rules(None).expect("legacy rules").is_empty());

    // Case B: PFN_ONLY_NON_APPCONTAINER (pfn_only_host) & NON_PACKAGED (unsigned_b2)
    // TerminateAndBlock(scope_to_package=true) skips persistent block save and releases transient containment.
    sender
        .send_with_package(
            SensorEvent::ProcessStart {
                identity: id_rb,
                parent_pid: 4,
                exe_path: pfn_only_exe.to_string(),
                command_line: "pfn_only_host.exe -Embedding".to_string(),
                user_sid: None,
            },
            ProcessPackageInfo {
                package_family_name: Some("Microsoft.Windows.Shell_cw5n1h2txyewy".to_string()),
                package_sid: None,
            },
        )
        .await
        .expect("send start PFN-only");
    sender
        .send_high_priority(SensorEvent::NetworkConnect {
            pid: id_rb.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 92)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms,
        })
        .await
        .expect("send net PFN-only");
    sender
        .send_with_package(
            SensorEvent::ProcessStart {
                identity: id_nonpkg,
                parent_pid: 4,
                exe_path: unsigned_exe.to_string(),
                command_line: "unsigned_b2.exe".to_string(),
                user_sid: None,
            },
            ProcessPackageInfo {
                package_family_name: None,
                package_sid: None,
            },
        )
        .await
        .expect("send start nonpkg");
    sender
        .send_high_priority(SensorEvent::NetworkConnect {
            pid: id_nonpkg.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 93)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms,
        })
        .await
        .expect("send net nonpkg");
    wait_high_priority_processed(&engine, 6, "PFN-only and non-pkg outbound alerts").await;

    let transient_rb_handle = defense
        .added_wfp()
        .iter()
        .find(|c| c.exe_path.eq_ignore_ascii_case(pfn_only_exe) && !c.allow && c.remote_ip.is_none())
        .expect("transient PFN-only handle")
        .handle;
    let alert_rb = store
        .list_alerts(Some(AlertStatus::Pending), 10)
        .expect("list")
        .into_iter()
        .find(|a| a.process_instance_id.as_deref() == Some(id_rb.instance_id().as_str()))
        .expect("alert_rb");
    let alert_nonpkg = store
        .list_alerts(Some(AlertStatus::Pending), 10)
        .expect("list")
        .into_iter()
        .find(|a| a.process_instance_id.as_deref() == Some(id_nonpkg.instance_id().as_str()))
        .expect("alert_nonpkg");

    // Case C: AllowPermanent(scope_to_package=true) fail-closed checks on Layer 3:
    // - PFN_ONLY_NON_APPCONTAINER (missing package_sid) -> Err
    assert!(engine
        .resolve_alert_scoped_with_outcome(
            &alert_rb.alert_id,
            AlertDecision::AllowPermanent {
                use_signer_if_available: true,
                allow_dest: None,
            },
            true,
        )
        .is_err());
    // - Missing use_signer_if_available -> Err
    let alert_no_pfn_id = "ALERT-SC-NO-PFN";
    store
        .record_alert(&AlertRecord {
            alert_id: alert_no_pfn_id.to_string(),
            timestamp_ms: now_ms,
            severity: AlertSeverity::Medium,
            source_layer: "LAYER_3_NETWORK".to_string(),
            rule_id: "NET_OUTBOUND_ENFORCE".to_string(),
            title: "Outbound".to_string(),
            process_instance_id: None,
            process_suspended: false,
            status: AlertStatus::Pending,
            context_json: serde_json::json!({
                "exe_path": bth_exe,
                "signer_subject": signer,
                "root_thumbprint": root_tp,
                "package_sid": "S-1-15-2-9999-1",
                "dst_ip": "198.51.100.94",
                "dst_port": 443
            })
            .to_string(),
            resolved_at_ms: None,
        })
        .expect("record alert_no_pfn");
    // Missing package_family_name -> Err
    assert!(engine
        .resolve_alert_scoped_with_outcome(
            alert_no_pfn_id,
            AlertDecision::AllowPermanent {
                use_signer_if_available: true,
                allow_dest: None,
            },
            true,
        )
        .is_err());
    // Unsigned binary even with PFN+SID -> Err (L-04)
    let alert_unsigned_scoped_id = "ALERT-SC-UNSIGNED";
    store
        .record_alert(&AlertRecord {
            alert_id: alert_unsigned_scoped_id.to_string(),
            timestamp_ms: now_ms,
            severity: AlertSeverity::Medium,
            source_layer: "LAYER_3_NETWORK".to_string(),
            rule_id: "NET_OUTBOUND_ENFORCE".to_string(),
            title: "Outbound".to_string(),
            process_instance_id: None,
            process_suspended: false,
            status: AlertStatus::Pending,
            context_json: serde_json::json!({
                "exe_path": unsigned_exe,
                "package_family_name": "Contoso.Unsigned_1",
                "package_sid": "S-1-15-2-9999-2",
                "dst_ip": "198.51.100.95",
                "dst_port": 443
            })
            .to_string(),
            resolved_at_ms: None,
        })
        .expect("record alert_unsigned_scoped");
    assert!(engine
        .resolve_alert_scoped_with_outcome(
            alert_unsigned_scoped_id,
            AlertDecision::AllowPermanent {
                use_signer_if_available: false,
                allow_dest: None,
            },
            true,
        )
        .is_err());
    assert!(engine
        .resolve_alert_scoped_with_outcome(
            alert_unsigned_scoped_id,
            AlertDecision::AllowPermanent {
                use_signer_if_available: true,
                allow_dest: None,
            },
            true,
        )
        .is_err());

    // Now resolve alert_rb & alert_nonpkg via TerminateAndBlock(scope_to_package=true):
    // both succeed with saved_rule_id == None and release transient containment.
    let scoped_before = store.list_scoped_rules(None).expect("list").len();
    let out_rb = engine
        .resolve_alert_scoped_with_outcome(
            &alert_rb.alert_id,
            AlertDecision::TerminateAndBlock {
                add_block_rule: true,
            },
            true,
        )
        .expect("resolve PFN-only terminate");
    assert_eq!(out_rb.saved_rule_id, None);
    assert!(defense.removed_wfp().contains(&transient_rb_handle));

    let out_nonpkg = engine
        .resolve_alert_scoped_with_outcome(
            &alert_nonpkg.alert_id,
            AlertDecision::TerminateAndBlock {
                add_block_rule: true,
            },
            true,
        )
        .expect("resolve non-packaged terminate");
    assert_eq!(out_nonpkg.saved_rule_id, None);
    assert_eq!(store.list_scoped_rules(None).expect("list").len(), scoped_before);

    engine.shutdown_and_flush().await.expect("shutdown");
}

#[tokio::test]
async fn daemon_fu_p4_03_b2_prg_001_single_candidate_sid_mismatch_refuses_attribution() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockDefense::new());
    let inspector = Arc::new(MapBinaryInspector::default());

    let bth_exe = r"C:\Windows\System32\backgroundTaskHost.exe";
    inspector.insert(
        bth_exe,
        BinaryIdentity {
            exe_path: bth_exe.to_string(),
            sha256: Some("c".repeat(64)),
            authenticode: None,
        },
    );

    let engine = DaemonEngine::start_with_all_dependencies(
        store.clone(),
        SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
        EarlyPruner::default(),
        DaemonConfig {
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::Enforce,
            wfp_drop_dns_grace_ms: 0,
            wfp_drop_attribution_grace_ms: 0,
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(RecordingNotifier::default()),
        Arc::clone(&inspector) as Arc<dyn BinaryInspector>,
        Arc::new(NullLiveProcessInspector),
    );

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
    let id_b = ProcessIdentity::new(47_401, unix_ms_to_filetime(now_ms - 1_000));
    let sid_b = "S-1-15-2-4444-2";
    let pfn_b = "Contoso.CandB_8wekyb3d8bbwe";
    let sid_a = "S-1-15-2-3333-1";

    engine
        .sender()
        .send_with_package(
            SensorEvent::ProcessStart {
                identity: id_b,
                parent_pid: 4,
                exe_path: bth_exe.to_string(),
                command_line: "backgroundTaskHost.exe -ServerName:CandB".to_string(),
                user_sid: None,
            },
            ProcessPackageInfo {
                package_family_name: Some(pfn_b.to_string()),
                package_sid: Some(sid_b.to_string()),
            },
        )
        .await
        .expect("send start CandB");
    wait_high_priority_processed(&engine, 1, "start CandB").await;

    assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
        os_filter_id: 701,
        rule_handle: 701,
        exe_path: bth_exe.to_string(),
        protocol: 6,
        dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 120)),
        dst_port: 443,
        timestamp_ms: now_ms,
        package_sid: Some(sid_a.to_string()),
    }));

    let deadline = Instant::now() + Duration::from_secs(2);
    while store.list_alerts(None, 10).expect("list").is_empty() {
        assert!(Instant::now() < deadline, "timed out waiting for PRG-001 drop alert");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    engine.shutdown_and_flush().await.expect("shutdown");

    let alerts = store.list_alerts(None, 10).expect("list alerts");
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].process_instance_id, None);
    assert!(
        !defense.suspends().contains(&id_b),
        "PRG-001: Candidate B must NOT be suspended when WFP event carries SID A"
    );
    let ctx: serde_json::Value = serde_json::from_str(&alerts[0].context_json).expect("parse ctx");
    assert_eq!(ctx["attribution"], "app_level_ambiguous");
    assert_eq!(ctx["package_sid"], sid_a);
    assert!(ctx["package_family_name"].is_null());
}

#[tokio::test]
async fn daemon_fu_p4_03_b2_layer1_process_allow_and_layer2_canary_scoped_eval() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockDefense::new());
    let inspector = Arc::new(MapBinaryInspector::default());

    let rb_exe = r"C:\Windows\System32\RuntimeBroker.exe";
    let rb_sha = "1".repeat(64);
    inspector.insert(
        rb_exe,
        BinaryIdentity {
            exe_path: rb_exe.to_string(),
            sha256: Some(rb_sha.clone()),
            authenticode: None,
        },
    );

    let sigma_rule = SigmaRule {
        id: "TEST-B2-RB-PROC".to_string(),
        title: "RuntimeBroker Exec Rule".to_string(),
        severity: AlertSeverity::Medium,
        description: None,
        conditions: vec![FieldCondition {
            field: SigmaField::Image,
            modifier: MatchModifier::EndsWith,
            values: vec![r"\RuntimeBroker.exe".to_string()],
        }],
    };
    let pruner = EarlyPruner::default();

    let engine = DaemonEngine::start_with_all_dependencies(
        store.clone(),
        SigmaEngine::from_rules(vec![sigma_rule]).expect("compile sigma"),
        pruner,
        DaemonConfig {
            outbound_firewall_enabled: false,
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(RecordingNotifier::default()),
        Arc::clone(&inspector) as Arc<dyn BinaryInspector>,
        Arc::new(NullLiveProcessInspector),
    );

    let process_allow = ScopedPolicyRuleRecord {
        rule_id: "SC-PROC-RB-1".to_string(),
        scope: RuleScope::ProcessAllow,
        exe_path_pattern: rb_exe.to_string(),
        sha256: Some(rb_sha.clone()),
        signer_subject: None,
        root_thumbprint: None,
        allowed_target: None,
        package_family_name: Some("Microsoft.Windows.Shell_cw5n1h2txyewy".to_string()),
        package_sid: None,
        command_line_pattern: Some("*-Embedding".to_string()),
        created_at_ms: 1_750_000_000_000,
        created_by: "test_b2".to_string(),
    };
    let canary_allow = ScopedPolicyRuleRecord {
        rule_id: "SC-CANARY-RB-1".to_string(),
        scope: RuleScope::FileCanaryAllow,
        exe_path_pattern: rb_exe.to_string(),
        sha256: Some(rb_sha),
        signer_subject: None,
        root_thumbprint: None,
        allowed_target: Some(r"C:\Users\*\Documents\*.txt".to_string()),
        package_family_name: Some("Contoso.Reader_111".to_string()),
        package_sid: None,
        command_line_pattern: Some("*-reader*".to_string()),
        created_at_ms: 1_750_000_000_001,
        created_by: "test_b2".to_string(),
    };
    engine
        .upsert_scoped_policy_rule(&process_allow)
        .expect("upsert ProcessAllow");
    engine
        .upsert_scoped_policy_rule(&canary_allow)
        .expect("upsert FileCanaryAllow");

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
    let id_proc_ok = ProcessIdentity::new(47_501, unix_ms_to_filetime(now_ms - 4_000));
    let id_proc_bad = ProcessIdentity::new(47_502, unix_ms_to_filetime(now_ms - 3_000));
    let id_canary_ok = ProcessIdentity::new(47_503, unix_ms_to_filetime(now_ms - 2_000));
    let id_canary_bad = ProcessIdentity::new(47_504, unix_ms_to_filetime(now_ms - 1_000));
    let sender = engine.sender();

    // 1. Layer 1 ProcessAllow: matching PFN+cmdline suppresses Sigma; non-matching cmdline alerts.
    sender
        .send_with_package(
            SensorEvent::ProcessStart {
                identity: id_proc_ok,
                parent_pid: 4,
                exe_path: rb_exe.to_string(),
                command_line: "RuntimeBroker.exe -Embedding".to_string(),
                user_sid: None,
            },
            ProcessPackageInfo {
                package_family_name: Some("Microsoft.Windows.Shell_cw5n1h2txyewy".to_string()),
                package_sid: None,
            },
        )
        .await
        .expect("send id_proc_ok");
    sender
        .send_with_package(
            SensorEvent::ProcessStart {
                identity: id_proc_bad,
                parent_pid: 4,
                exe_path: rb_exe.to_string(),
                command_line: "RuntimeBroker.exe -UnexpectedArg".to_string(),
                user_sid: None,
            },
            ProcessPackageInfo {
                package_family_name: Some("Microsoft.Windows.Shell_cw5n1h2txyewy".to_string()),
                package_sid: None,
            },
        )
        .await
        .expect("send id_proc_bad");

    // 2. Layer 2 FileCanaryAllow: matching PFN+cmdline+target allowed; sibling PFN alerts.
    sender
        .send_with_package(
            SensorEvent::ProcessStart {
                identity: id_canary_ok,
                parent_pid: 4,
                exe_path: rb_exe.to_string(),
                command_line: "RuntimeBroker.exe -reader-mode".to_string(),
                user_sid: None,
            },
            ProcessPackageInfo {
                package_family_name: Some("Contoso.Reader_111".to_string()),
                package_sid: None,
            },
        )
        .await
        .expect("send id_canary_ok");
    sender
        .send_with_package(
            SensorEvent::ProcessStart {
                identity: id_canary_bad,
                parent_pid: 4,
                exe_path: rb_exe.to_string(),
                command_line: "RuntimeBroker.exe -reader-mode".to_string(),
                user_sid: None,
            },
            ProcessPackageInfo {
                package_family_name: Some("Contoso.Evil_222".to_string()),
                package_sid: None,
            },
        )
        .await
        .expect("send id_canary_bad");
    wait_high_priority_processed(&engine, 4, "four RuntimeBroker starts").await;

    sender
        .send(SensorEvent::CanaryFileAccess {
            pid: id_canary_ok.pid,
            target_path: r"C:\Users\Alice\Documents\notes.txt".to_string(),
            category: CanaryCategory::Honeypot,
            access_mask: 0x2,
            is_write_or_delete: true,
            timestamp_ms: now_ms,
        })
        .await
        .expect("send canary ok");
    sender
        .send(SensorEvent::CanaryFileAccess {
            pid: id_canary_bad.pid,
            target_path: r"C:\Users\Alice\Documents\notes.txt".to_string(),
            category: CanaryCategory::Honeypot,
            access_mask: 0x2,
            is_write_or_delete: true,
            timestamp_ms: now_ms,
        })
        .await
        .expect("send canary bad");
    wait_high_priority_processed(&engine, 6, "two CanaryFileAccess events").await;
    engine.shutdown_and_flush().await.expect("shutdown");

    let alerts = store.list_alerts(None, 20).expect("list alerts");
    let proc_alerts: Vec<&AlertRecord> = alerts
        .iter()
        .filter(|a| a.source_layer == "LAYER_2_RULES")
        .collect();
    // Sigma rule matches all 4 ProcessStarts except id_proc_ok (which matches ProcessAllow);
    // verify id_proc_ok has 0 LAYER_2_RULES alerts while id_proc_bad has 1.
    assert!(
        !proc_alerts
            .iter()
            .any(|a| a.process_instance_id.as_deref() == Some(id_proc_ok.instance_id().as_str())),
        "matching ProcessAllow command line must suppress LAYER_2_RULES alert"
    );
    assert!(
        proc_alerts
            .iter()
            .any(|a| a.process_instance_id.as_deref() == Some(id_proc_bad.instance_id().as_str())),
        "non-matching command line must still trigger LAYER_2_RULES alert"
    );

    let canary_alerts: Vec<&AlertRecord> = alerts
        .iter()
        .filter(|a| a.source_layer == "LAYER_1_CANARY")
        .collect();
    assert_eq!(canary_alerts.len(), 1, "expected 1 canary alert, got {canary_alerts:?}");
    assert_eq!(
        canary_alerts[0].process_instance_id.as_deref(),
        Some(id_canary_bad.instance_id().as_str())
    );
}
