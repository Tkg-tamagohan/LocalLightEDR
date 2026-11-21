//! Phase 4A integration tests for `ledr-daemon` (`DAEMON-P4-01`..`DAEMON-P4-14`):
//! `ReportDownloadOrigin`, 3-stage MOTW attribution, `L-18` pre-emptive WFP restrictions,
//! `ReportBrowserEvent` severity/dedup/`L-19` notification suppression, `LAYER_4_BROWSER`
//! alert resolution, bridge IPC auth, `spawn_blocking` responsiveness, and burst budget.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use ledr_daemon::{
    start_ipc_server, verify_caller_identity, ActiveProcessEntry, BinaryInspector,
    BrowserEventOutcome, BrowserReportError, DaemonConfig, DaemonEngine, LiveProcessInspector,
    MotwInspector, MotwMatchStage, NotificationDispatcher, OutboundEnforcementMode,
    WindowsBinaryInspector, WindowsMotwInspector, MAX_BROWSER_EVENT_DETAILS_BYTES,
};
use ledr_proto::{
    read_ipc_frame, write_ipc_frame, ActiveDefenseController, AlertDecision, AlertRecord,
    AlertSeverity, AlertStatus, AllowlistRuleRecord, AuthenticodeInfo, BrowserSecurityEventType,
    CanaryCategory, IpcRequest, IpcResponse, ProcessIdentity, RuleScope, SensorEvent,
    ACTIVE_PROCESS_TABLE_CAPACITY, AUTHORIZED_BRIDGE_EXE_PATH, HIGH_PRIORITY_CHANNEL_CAPACITY,
    TELEMETRY_CHANNEL_CAPACITY,
};
use ledr_rules::{
    compute_file_sha256_hex, BinaryIdentity, EarlyPruner, SigmaEngine,
};
use ledr_sensor_win::etw::LiveProcessInfo;
use ledr_sensor_win::{write_zone_identifier, MotwZoneInfo};
use ledr_store::LedrStore;

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

#[derive(Default)]
struct MockDefense {
    next_handle: AtomicU64,
    suspends: Mutex<Vec<ProcessIdentity>>,
    resumes: Mutex<Vec<ProcessIdentity>>,
    terminates: Mutex<Vec<ProcessIdentity>>,
    added_wfp: Mutex<Vec<WfpCall>>,
    removed_wfp: Mutex<Vec<u64>>,
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

    fn added_wfp(&self) -> Vec<WfpCall> {
        self.added_wfp.lock().expect("lock added_wfp").clone()
    }

    fn removed_wfp(&self) -> Vec<u64> {
        self.removed_wfp.lock().expect("lock removed_wfp").clone()
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

    fn remove_wfp_rule(&self, filter_id: u64) -> Result<(), String> {
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
    entered: Arc<(Mutex<bool>, Condvar)>,
    released: Arc<(Mutex<bool>, Condvar)>,
}

impl MotwInspector for BlockingGateMotwInspector {
    fn read_zone_identifier(&self, _path: &Path) -> Option<MotwZoneInfo> {
        {
            let (lock, cvar) = &*self.entered;
            let mut flag = lock.lock().expect("lock entered");
            *flag = true;
            cvar.notify_all();
        }
        {
            let (lock, cvar) = &*self.released;
            let mut flag = lock.lock().expect("lock released");
            while !*flag {
                flag = cvar.wait(flag).expect("wait released");
            }
        }
        None
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
    let entered = Arc::new((Mutex::new(false), Condvar::new()));
    let released = Arc::new((Mutex::new(false), Condvar::new()));
    let _release_guard = GateReleaseGuard(Arc::clone(&released));

    let blocking_motw = Arc::new(BlockingGateMotwInspector {
        entered: Arc::clone(&entered),
        released: Arc::clone(&released),
    });

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

    // Deterministically wait until `dispatch_request` has entered `BlockingGateMotwInspector`
    // inside `spawn_blocking`, then confirm the current-thread Tokio runtime still drives
    // both async tasks and concurrent `Ping` IPC requests immediately.
    let entered_wait = Arc::clone(&entered);
    tokio::task::spawn_blocking(move || {
        let (lock, cvar) = &*entered_wait;
        let mut flag = lock.lock().expect("lock entered");
        while !*flag {
            flag = cvar.wait(flag).expect("wait entered");
        }
    })
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
