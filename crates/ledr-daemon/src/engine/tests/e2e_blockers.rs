use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use ledr_proto::{
    ActiveDefenseController, AlertRecord, AlertSeverity, AlertStatus, AllowlistRuleRecord,
    CanaryCategory, ProcessIdentity, RuleScope, SensorEvent,
};
use ledr_rules::{EarlyPruner, SigmaEngine};
use ledr_store::LedrStore;

use super::helpers::{send_process_start, start_stopped_engine, FixedShaInspector, StubNotifier};
use super::{current_unix_ms, DaemonConfig, DaemonEngine, EventLane};
use crate::engine::OutboundEnforcementMode;

struct RecordingDefense {
    next_handle: AtomicU64,
    suspended: Mutex<Vec<ProcessIdentity>>,
    resumed: Mutex<Vec<ProcessIdentity>>,
    wfp_blocks_added: Mutex<Vec<String>>,
}

impl RecordingDefense {
    fn new() -> Self {
        Self {
            next_handle: AtomicU64::new(500),
            suspended: Mutex::new(Vec::new()),
            resumed: Mutex::new(Vec::new()),
            wfp_blocks_added: Mutex::new(Vec::new()),
        }
    }

    fn suspended(&self) -> Vec<ProcessIdentity> {
        self.suspended
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn resumed(&self) -> Vec<ProcessIdentity> {
        self.resumed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn wfp_blocks_added(&self) -> Vec<String> {
        self.wfp_blocks_added
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

impl ActiveDefenseController for RecordingDefense {
    fn suspend_process(&self, target: &ProcessIdentity, _include_children: bool) -> Result<(), String> {
        self.suspended
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(*target);
        Ok(())
    }

    fn resume_process(&self, target: &ProcessIdentity) -> Result<(), String> {
        self.resumed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(*target);
        Ok(())
    }

    fn terminate_process(
        &self,
        _target: &ProcessIdentity,
        _include_children: bool,
    ) -> Result<(), String> {
        Ok(())
    }

    fn add_wfp_app_rule(
        &self,
        exe_path: &Path,
        _remote_ip: Option<IpAddr>,
        allow: bool,
    ) -> Result<u64, String> {
        if !allow {
            self.wfp_blocks_added
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(exe_path.to_string_lossy().into_owned());
        }
        Ok(self.next_handle.fetch_add(1, Ordering::Relaxed))
    }

    fn remove_wfp_rule(&self, _filter_id: u64) -> Result<(), String> {
        Ok(())
    }
}

#[tokio::test]
async fn outbound_mode_preemptive_only_skips_unknown_and_enforces_preemptive_and_block() {
    let store = LedrStore::open_in_memory().expect("in-memory store");
    let defense = Arc::new(RecordingDefense::new());
    let inspector = Arc::new(FixedShaInspector("a".repeat(64)));

    // Explicit NetworkBlock rule for blocked_app.exe
    store
        .upsert_rule(&AllowlistRuleRecord {
            rule_id: "BLK-EXPLICIT-1".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: r"C:\Apps\blocked_app.exe".to_string(),
            sha256: None,
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("198.51.100.77".to_string()),
            created_at_ms: 1_732_000_000_000,
            created_by: "test".to_string(),
        })
        .expect("insert NetworkBlock");

    let config = DaemonConfig {
        outbound_firewall_enabled: true,
        outbound_enforcement_mode: OutboundEnforcementMode::PreemptiveOnly,
        ..DaemonConfig::default()
    };
    let engine = start_stopped_engine(
        store.clone(),
        config,
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        inspector,
    )
    .await;

    let now_ms = current_unix_ms();
    let unknown_id = ProcessIdentity::new(41001, 1001);
    let script_id = ProcessIdentity::new(41002, 1002);
    let blocked_id = ProcessIdentity::new(41003, 1003);

    send_process_start(&engine, unknown_id, r"C:\Apps\editor.exe");
    send_process_start(&engine, script_id, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");
    send_process_start(&engine, blocked_id, r"C:\Apps\blocked_app.exe");

    // 1. GeneralUnknown: must record non-suspended alert without WFP block or suspension.
    let _ = engine.process_event_with_lane(
        &SensorEvent::NetworkConnect {
            pid: unknown_id.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            dst_port: 443,
            domain_hint: Some("example.com".to_string()),
            timestamp_ms: now_ms,
        },
        EventLane::HighPriority,
    );
    assert!(
        !defense.suspended().contains(&unknown_id),
        "PreemptiveOnly must NOT suspend GeneralUnknown"
    );
    assert!(
        !defense
            .wfp_blocks_added()
            .iter()
            .any(|p| p.eq_ignore_ascii_case(r"C:\Apps\editor.exe")),
        "PreemptiveOnly must NOT WFP-block GeneralUnknown"
    );

    // 2. ScriptInterpreter: MUST be WFP-blocked and suspended.
    let _ = engine.process_event_with_lane(
        &SensorEvent::NetworkConnect {
            pid: script_id.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms + 1,
        },
        EventLane::HighPriority,
    );
    assert!(
        defense.suspended().contains(&script_id),
        "PreemptiveOnly MUST suspend ScriptInterpreter"
    );
    assert!(
        defense
            .wfp_blocks_added()
            .iter()
            .any(|p| p.to_ascii_lowercase().ends_with("powershell.exe")),
        "PreemptiveOnly MUST WFP-block ScriptInterpreter"
    );

    // 3. Explicit NetworkBlock: MUST install WFP block.
    let _ = engine.process_event_with_lane(
        &SensorEvent::NetworkConnect {
            pid: blocked_id.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms + 2,
        },
        EventLane::HighPriority,
    );
    assert!(
        defense
            .wfp_blocks_added()
            .iter()
            .any(|p| p.eq_ignore_ascii_case(r"C:\Apps\blocked_app.exe")),
        "PreemptiveOnly MUST enforce explicit NetworkBlock"
    );

    let alerts = store.list_alerts(None, 20).expect("list alerts");
    let unknown_alert = alerts
        .iter()
        .find(|a| a.process_instance_id.as_deref() == Some("41001:1001"))
        .expect("unknown alert recorded");
    assert!(!unknown_alert.process_suspended);
    let script_alert = alerts
        .iter()
        .find(|a| a.process_instance_id.as_deref() == Some("41002:1002"))
        .expect("script alert recorded");
    assert!(script_alert.process_suspended);
}

#[tokio::test]
async fn outbound_mode_audit_never_suspends_or_adds_wfp_blocks() {
    let store = LedrStore::open_in_memory().expect("in-memory store");
    let defense = Arc::new(RecordingDefense::new());
    let inspector = Arc::new(FixedShaInspector("b".repeat(64)));

    // Seed both a literal-IP and a domain-scoped NetworkBlock rule to verify Audit mode
    // never installs WFP filters during startup reconciliation, rule upsert, or DnsQuery
    // pre-materialization.
    store
        .upsert_rule(&AllowlistRuleRecord {
            rule_id: "BLK-AUDIT-IP".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: r"C:\Apps\unknown.exe".to_string(),
            sha256: None,
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("198.51.100.88".to_string()),
            created_at_ms: 1_732_000_000_000,
            created_by: "test".to_string(),
        })
        .expect("insert literal NetworkBlock");
    store
        .upsert_rule(&AllowlistRuleRecord {
            rule_id: "BLK-AUDIT-DOMAIN".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: r"C:\Apps\unknown.exe".to_string(),
            sha256: None,
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("c2.audit-blocked.example".to_string()),
            created_at_ms: 1_732_000_000_000,
            created_by: "test".to_string(),
        })
        .expect("insert domain NetworkBlock");

    let config = DaemonConfig {
        outbound_firewall_enabled: true,
        outbound_enforcement_mode: OutboundEnforcementMode::Audit,
        preemptive_startup_executables: vec![
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
        ],
        ..DaemonConfig::default()
    };
    let engine = start_stopped_engine(
        store.clone(),
        config,
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        inspector,
    )
    .await;

    let report = engine.deploy_persisted_network_rules();
    assert_eq!(report.applied, 0);
    assert_eq!(report.failed, 0);

    let now_ms = current_unix_ms();
    let created_ms = now_ms - 1_000;
    let created_100ns = 116_444_736_000_000_000u64 + (created_ms as u64) * 10_000;
    let script_id = ProcessIdentity::new(42001, created_100ns);
    let unknown_id = ProcessIdentity::new(42002, created_100ns + 1);

    send_process_start(
        &engine,
        script_id,
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    );
    send_process_start(&engine, unknown_id, r"C:\Apps\unknown.exe");

    let event_ts_ms = current_unix_ms();

    // DNS resolution for a domain-scoped NetworkBlock must not pre-materialize WFP filters in Audit mode.
    let _ = engine.process_event_with_lane(
        &SensorEvent::DnsQuery {
            pid: unknown_id.pid,
            query_name: "c2.audit-blocked.example".to_string(),
            query_type: 1,
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 89))],
            timestamp_ms: event_ts_ms,
        },
        EventLane::HighPriority,
    );

    for (pid, dst_ip) in [
        (script_id.pid, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 40))),
        (unknown_id.pid, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 88))),
        (unknown_id.pid, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 41))),
    ] {
        let _ = engine.process_event_with_lane(
            &SensorEvent::NetworkConnect {
                pid,
                protocol: 6,
                dst_ip,
                dst_port: 443,
                domain_hint: None,
                timestamp_ms: event_ts_ms,
            },
            EventLane::HighPriority,
        );
    }

    assert!(
        defense.suspended().is_empty(),
        "Audit mode must never suspend processes"
    );
    assert!(
        defense.wfp_blocks_added().is_empty(),
        "Audit mode must never install WFP block filters (startup, DnsQuery, or NetworkConnect)"
    );
    let alerts = store.list_alerts(None, 20).expect("list alerts");
    assert_eq!(alerts.len(), 3);
    assert!(alerts.iter().all(|a| !a.process_suspended));
}

#[tokio::test]
async fn shutdown_resumes_unresolved_suspended_processes_only_when_configured() {
    let parent_pending = ProcessIdentity::new(51001, 11111);
    let child_pending = ProcessIdentity::new(51002, 22222);
    let parent_expired = ProcessIdentity::new(51003, 33333);
    let parent_resolved = ProcessIdentity::new(51004, 44444);
    let parent_unsuspended = ProcessIdentity::new(51005, 55555);
    let orphan_suspended_child = ProcessIdentity::new(51006, 66666);

    let seed_alerts = |store: &LedrStore| {
        store
            .record_alert(&AlertRecord {
                alert_id: "alert-pending".to_string(),
                timestamp_ms: 1_732_000_000_000,
                severity: AlertSeverity::Critical,
                source_layer: "LAYER_1_CANARY".to_string(),
                rule_id: "LEDR-CANARY-HONEYPOT".to_string(),
                title: "Pending suspended".to_string(),
                process_instance_id: Some(parent_pending.instance_id()),
                process_suspended: true,
                status: AlertStatus::Pending,
                context_json: serde_json::json!({
                    "suspended_children": [child_pending.instance_id()]
                })
                .to_string(),
                resolved_at_ms: None,
            })
            .expect("seed pending");
        store
            .record_alert(&AlertRecord {
                alert_id: "alert-child-only".to_string(),
                timestamp_ms: 1_732_000_000_000,
                severity: AlertSeverity::Critical,
                source_layer: "LAYER_1_CANARY".to_string(),
                rule_id: "LEDR-CANARY-HONEYPOT".to_string(),
                title: "Parent not suspended, child suspended".to_string(),
                process_instance_id: Some(parent_unsuspended.instance_id()),
                process_suspended: false,
                status: AlertStatus::Pending,
                context_json: serde_json::json!({
                    "suspended_children": [orphan_suspended_child.instance_id()]
                })
                .to_string(),
                resolved_at_ms: None,
            })
            .expect("seed child-only");
        store
            .record_alert(&AlertRecord {
                alert_id: "alert-expired".to_string(),
                timestamp_ms: 1_732_000_000_001,
                severity: AlertSeverity::High,
                source_layer: "LAYER_3_NETWORK".to_string(),
                rule_id: "LEDR-NET-UNKNOWN-OUTBOUND".to_string(),
                title: "Expired suspended".to_string(),
                process_instance_id: Some(parent_expired.instance_id()),
                process_suspended: true,
                status: AlertStatus::ExpiredSuspended,
                context_json: "{}".to_string(),
                resolved_at_ms: None,
            })
            .expect("seed expired");
        store
            .record_alert(&AlertRecord {
                alert_id: "alert-resolved".to_string(),
                timestamp_ms: 1_732_000_000_002,
                severity: AlertSeverity::High,
                source_layer: "LAYER_1_CANARY".to_string(),
                rule_id: "LEDR-CANARY-COOKIE".to_string(),
                title: "Already resolved".to_string(),
                process_instance_id: Some(parent_resolved.instance_id()),
                process_suspended: true,
                status: AlertStatus::ApprovedOnce,
                context_json: "{}".to_string(),
                resolved_at_ms: Some(1_732_000_001_000),
            })
            .expect("seed resolved");
    };

    // Case 1: resume_suspended_on_shutdown = true (foreground / safe-shutdown mode).
    let store_on = LedrStore::open_in_memory().expect("store_on");
    seed_alerts(&store_on);
    let defense_on = Arc::new(RecordingDefense::new());
    let engine_on = DaemonEngine::start_with_dependencies(
        store_on,
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            resume_suspended_on_shutdown: true,
            ..DaemonConfig::default()
        },
        Arc::clone(&defense_on) as Arc<dyn ActiveDefenseController>,
        Arc::new(StubNotifier),
        Arc::new(FixedShaInspector("c".repeat(64))),
    );
    engine_on.shutdown_and_flush().await.expect("shutdown_on");

    let resumed = defense_on.resumed();
    assert!(resumed.contains(&parent_pending));
    assert!(resumed.contains(&child_pending));
    assert!(resumed.contains(&parent_expired));
    assert!(
        resumed.contains(&orphan_suspended_child),
        "recorded suspended_children must be resumed even when parent process_suspended=false"
    );
    assert!(
        !resumed.contains(&parent_unsuspended),
        "non-suspended parent must not be resumed"
    );
    assert!(
        !resumed.contains(&parent_resolved),
        "already-resolved alerts must not be resumed on shutdown"
    );

    // Case 2: resume_suspended_on_shutdown = false (Windows Service mode, L-07 containment).
    let store_off = LedrStore::open_in_memory().expect("store_off");
    seed_alerts(&store_off);
    let defense_off = Arc::new(RecordingDefense::new());
    let engine_off = DaemonEngine::start_with_dependencies(
        store_off,
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            resume_suspended_on_shutdown: false,
            ..DaemonConfig::default()
        },
        Arc::clone(&defense_off) as Arc<dyn ActiveDefenseController>,
        Arc::new(StubNotifier),
        Arc::new(FixedShaInspector("c".repeat(64))),
    );
    engine_off.shutdown_and_flush().await.expect("shutdown_off");
    assert!(
        defense_off.resumed().is_empty(),
        "service mode (resume_suspended_on_shutdown = false) must preserve L-07 containment"
    );
}

#[tokio::test]
async fn canary_file_access_backfills_unregistered_live_pid_and_suspends() {
    let store = LedrStore::open_in_memory().expect("in-memory store");
    let defense = Arc::new(RecordingDefense::new());
    let inspector = Arc::new(FixedShaInspector("d".repeat(64)));

    let engine = start_stopped_engine(
        store.clone(),
        DaemonConfig::default(),
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        inspector,
    )
    .await;

    // Deliberately do NOT send ProcessStart for the current test runner PID to simulate
    // the ETW cross-provider race (Kernel-File arriving before Kernel-Process).
    let live_pid = std::process::id();
    let _ = engine.process_event_with_lane(
        &SensorEvent::CanaryFileAccess {
            pid: live_pid,
            target_path: r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies".to_string(),
            category: CanaryCategory::CookieDb,
            access_mask: 0x0012_0089,
            is_write_or_delete: false,
            timestamp_ms: current_unix_ms(),
        },
        EventLane::HighPriority,
    );

    let suspended = defense.suspended();
    assert_eq!(
        suspended.len(),
        1,
        "on-demand PID backfill must populate non-zero create_time_100ns and trigger suspend"
    );
    assert_eq!(suspended[0].pid, live_pid);
    assert_ne!(suspended[0].create_time_100ns, 0);

    let alerts = store.list_alerts(None, 10).expect("list alerts");
    assert_eq!(alerts.len(), 1);
    assert!(alerts[0].process_suspended);
    assert_eq!(
        alerts[0].process_instance_id.as_deref(),
        Some(suspended[0].instance_id().as_str())
    );
}

#[tokio::test]
async fn canary_file_access_backfill_does_not_overwrite_mismatched_create_time() {
    let store = LedrStore::open_in_memory().expect("in-memory store");
    let defense = Arc::new(RecordingDefense::new());
    let inspector = Arc::new(FixedShaInspector("e".repeat(64)));

    let engine = start_stopped_engine(
        store.clone(),
        DaemonConfig::default(),
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        inspector,
    )
    .await;

    // Register the current test runner PID with a distinct non-zero create_time_100ns and an
    // empty exe_path (simulating PID reuse before exe_path was populated). Backfill must NOT
    // overwrite the non-zero identity with the live OS process's creation time.
    let live_pid = std::process::id();
    let original_ident = ProcessIdentity::new(live_pid, 12_345);
    send_process_start(&engine, original_ident, "");

    let _ = engine.process_event_with_lane(
        &SensorEvent::CanaryFileAccess {
            pid: live_pid,
            target_path: r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies".to_string(),
            category: CanaryCategory::CookieDb,
            access_mask: 0x0012_0089,
            is_write_or_delete: false,
            timestamp_ms: current_unix_ms(),
        },
        EventLane::HighPriority,
    );

    let suspended = defense.suspended();
    assert_eq!(suspended.len(), 1);
    assert_eq!(
        suspended[0], original_ident,
        "backfill must not overwrite a non-zero create_time_100ns with a reused live PID's timestamp"
    );
}

#[tokio::test]
async fn pr21_bug_0001_canary_backfill_skips_live_process_started_after_event() {
    let store = LedrStore::open_in_memory().expect("in-memory store");
    let defense = Arc::new(RecordingDefense::new());
    let inspector = Arc::new(FixedShaInspector("f".repeat(64)));

    let engine = start_stopped_engine(
        store.clone(),
        DaemonConfig::default(),
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        inspector,
    )
    .await;

    // Event timestamp is far earlier than the current test runner process's real OS creation
    // time, simulating PID reuse where a newer process now occupies the PID.
    let live_pid = std::process::id();
    let _ = engine.process_event_with_lane(
        &SensorEvent::CanaryFileAccess {
            pid: live_pid,
            target_path: r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies".to_string(),
            category: CanaryCategory::CookieDb,
            access_mask: 0x0012_0089,
            is_write_or_delete: false,
            timestamp_ms: 1_000,
        },
        EventLane::HighPriority,
    );

    assert!(
        defense.suspended().is_empty(),
        "BUG_0001: reused live PID created after event_ts_ms must not be backfilled or suspended"
    );
    let alerts = store.list_alerts(None, 10).expect("list alerts");
    assert_eq!(alerts.len(), 1);
    assert!(!alerts[0].process_suspended);
    assert!(alerts[0].process_instance_id.is_none());
}

struct PartialResumeDefense {
    fail_target: ProcessIdentity,
    resumed: Mutex<Vec<ProcessIdentity>>,
}

impl PartialResumeDefense {
    fn new(fail_target: ProcessIdentity) -> Self {
        Self {
            fail_target,
            resumed: Mutex::new(Vec::new()),
        }
    }

    fn resumed(&self) -> Vec<ProcessIdentity> {
        self.resumed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

impl ActiveDefenseController for PartialResumeDefense {
    fn suspend_process(&self, _target: &ProcessIdentity, _include_children: bool) -> Result<(), String> {
        Ok(())
    }

    fn resume_process(&self, target: &ProcessIdentity) -> Result<(), String> {
        if *target == self.fail_target {
            return Err("access denied while resuming live child".to_string());
        }
        self.resumed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(*target);
        Ok(())
    }

    fn terminate_process(
        &self,
        _target: &ProcessIdentity,
        _include_children: bool,
    ) -> Result<(), String> {
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

#[tokio::test]
async fn pr21_bug_0002_shutdown_resume_clears_sqlite_suspension_and_unblocks_re_freeze() {
    let store = LedrStore::open_in_memory().expect("in-memory store");
    let parent_id = ProcessIdentity::new(62001, 100_001);
    let child_ok = ProcessIdentity::new(62002, 100_002);
    // Use the current live PID for child_fail so ProcessLiveness reports Running (not Gone).
    let child_fail = ProcessIdentity::new(std::process::id(), 100_003);

    store
        .record_alert(&AlertRecord {
            alert_id: "alert-pre-shutdown".to_string(),
            timestamp_ms: 1_732_000_000_000,
            severity: AlertSeverity::Critical,
            source_layer: "LAYER_1_CANARY".to_string(),
            rule_id: "LEDR-CANARY-HONEYPOT".to_string(),
            title: "Pre-shutdown suspended tree".to_string(),
            process_instance_id: Some(parent_id.instance_id()),
            process_suspended: true,
            status: AlertStatus::Pending,
            context_json: serde_json::json!({
                "suspended_children": [child_ok.instance_id(), child_fail.instance_id()]
            })
            .to_string(),
            resolved_at_ms: None,
        })
        .expect("seed pre-shutdown alert");

    let defense1 = Arc::new(PartialResumeDefense::new(child_fail));
    let engine1 = DaemonEngine::start_with_dependencies(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            resume_suspended_on_shutdown: true,
            ..DaemonConfig::default()
        },
        Arc::clone(&defense1) as Arc<dyn ActiveDefenseController>,
        Arc::new(StubNotifier),
        Arc::new(FixedShaInspector("a".repeat(64))),
    );
    engine1.shutdown_and_flush().await.expect("shutdown1");
    let first_resumed = defense1.resumed();
    assert!(first_resumed.contains(&parent_id));
    assert!(first_resumed.contains(&child_ok));
    assert!(!first_resumed.contains(&child_fail));

    // Verify SQLite cleared parent + child_ok, kept child_fail, and recorded audit metadata.
    let updated = store
        .get_alert("alert-pre-shutdown")
        .expect("get alert")
        .expect("alert exists");
    assert!(
        !updated.process_suspended,
        "BUG_0002: parent process_suspended must be cleared after confirmed shutdown resume"
    );
    let ctx: serde_json::Value =
        serde_json::from_str(&updated.context_json).expect("valid context_json");
    let remaining_children: Vec<&str> = ctx["suspended_children"]
        .as_array()
        .expect("suspended_children array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(
        remaining_children,
        vec![child_fail.instance_id().as_str()],
        "failed live child must remain in suspended_children while resumed child is removed"
    );
    let audit_ids: Vec<&str> = ctx["shutdown_resumed_identities"]
        .as_array()
        .expect("shutdown_resumed_identities array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(audit_ids.contains(&parent_id.instance_id().as_str()));
    assert!(audit_ids.contains(&child_ok.instance_id().as_str()));
    assert!(!audit_ids.contains(&child_fail.instance_id().as_str()));
    assert!(ctx["shutdown_resumed_at_ms"].as_i64().is_some());

    // Simulate restart: same parent gets re-frozen under a new alert; AllowOnce MUST resume it
    // instead of being blocked by the stale pre-shutdown alert.
    store
        .record_alert(&AlertRecord {
            alert_id: "alert-post-restart".to_string(),
            timestamp_ms: 1_732_000_010_000,
            severity: AlertSeverity::High,
            source_layer: "LAYER_1_CANARY".to_string(),
            rule_id: "LEDR-CANARY-COOKIE_DB".to_string(),
            title: "Post-restart re-freeze".to_string(),
            process_instance_id: Some(parent_id.instance_id()),
            process_suspended: true,
            status: AlertStatus::Pending,
            context_json: "{}".to_string(),
            resolved_at_ms: None,
        })
        .expect("seed post-restart alert");

    let defense2 = Arc::new(RecordingDefense::new());
    let engine2 = start_stopped_engine(
        store.clone(),
        DaemonConfig::default(),
        Arc::clone(&defense2) as Arc<dyn ActiveDefenseController>,
        Arc::new(FixedShaInspector("a".repeat(64))),
    )
    .await;

    engine2
        .resolve_alert("alert-post-restart", ledr_proto::AlertDecision::AllowOnce)
        .expect("AllowOnce after restart");
    assert!(
        defense2.resumed().contains(&parent_id),
        "BUG_0002: AllowOnce on re-frozen process must resume it without being blocked by pre-shutdown alert"
    );
}

#[tokio::test]
async fn pr21_bug_0003_shutdown_resume_scans_past_1000_non_suspended_alerts() {
    let store = LedrStore::open_in_memory().expect("in-memory store");
    let old_parent = ProcessIdentity::new(63001, 200_001);
    let old_child = ProcessIdentity::new(63002, 200_002);

    store
        .record_alert(&AlertRecord {
            alert_id: "old-parent-suspended".to_string(),
            timestamp_ms: 1_732_000_000_000,
            severity: AlertSeverity::High,
            source_layer: "LAYER_1_CANARY".to_string(),
            rule_id: "LEDR-CANARY-COOKIE_DB".to_string(),
            title: "Old parent suspended".to_string(),
            process_instance_id: Some(old_parent.instance_id()),
            process_suspended: true,
            status: AlertStatus::Pending,
            context_json: "{}".to_string(),
            resolved_at_ms: None,
        })
        .expect("seed old parent");
    store
        .record_alert(&AlertRecord {
            alert_id: "old-child-suspended".to_string(),
            timestamp_ms: 1_732_000_000_001,
            severity: AlertSeverity::Critical,
            source_layer: "LAYER_1_CANARY".to_string(),
            rule_id: "LEDR-CANARY-HONEYPOT".to_string(),
            title: "Old child-only suspended".to_string(),
            process_instance_id: Some("63003:200003".to_string()),
            process_suspended: false,
            status: AlertStatus::ExpiredSuspended,
            context_json: serde_json::json!({
                "suspended_children": [old_child.instance_id()]
            })
            .to_string(),
            resolved_at_ms: None,
        })
        .expect("seed old child");

    // Flood 1,050 newer non-suspended Pending alerts so a naive LIMIT 1000 query would miss the old rows.
    for i in 0..1050 {
        store
            .record_alert(&AlertRecord {
                alert_id: format!("flood-{i:04}"),
                timestamp_ms: 1_732_000_001_000 + i as i64,
                severity: AlertSeverity::Low,
                source_layer: "LAYER_2_SIGMA".to_string(),
                rule_id: "LEDR-FLOOD".to_string(),
                title: "Non-suspended noise".to_string(),
                process_instance_id: Some(format!("70000:{}", 300_000 + i)),
                process_suspended: false,
                status: AlertStatus::Pending,
                context_json: "{}".to_string(),
                resolved_at_ms: None,
            })
            .expect("seed flood alert");
    }

    let defense = Arc::new(RecordingDefense::new());
    let engine = DaemonEngine::start_with_dependencies(
        store,
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            resume_suspended_on_shutdown: true,
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(StubNotifier),
        Arc::new(FixedShaInspector("b".repeat(64))),
    );
    engine.shutdown_and_flush().await.expect("shutdown");

    let resumed = defense.resumed();
    assert!(
        resumed.contains(&old_parent),
        "BUG_0003: old parent-suspended alert beyond 1,000 newer alerts must be resumed"
    );
    assert!(
        resumed.contains(&old_child),
        "BUG_0003: old child-only suspended alert beyond 1,000 newer alerts must be resumed"
    );
}

struct CountingInspector {
    calls: std::sync::atomic::AtomicUsize,
    sha256: String,
}

impl CountingInspector {
    fn new(sha256: String) -> Self {
        Self {
            calls: std::sync::atomic::AtomicUsize::new(0),
            sha256,
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::Acquire)
    }
}

impl crate::engine::BinaryInspector for CountingInspector {
    fn inspect(&self, exe_path: &str) -> ledr_rules::BinaryIdentity {
        self.calls.fetch_add(1, Ordering::AcqRel);
        ledr_rules::BinaryIdentity {
            exe_path: exe_path.to_string(),
            sha256: Some(self.sha256.clone()),
            authenticode: None,
        }
    }
}

#[tokio::test]
async fn pr21_analysis_0001_dedup_fast_path_skips_binary_inspector_when_no_rule_matches_exe() {
    let store = LedrStore::open_in_memory().expect("in-memory store");
    // Seed default browser rule (does NOT match unrelated_app.exe).
    store
        .seed_default_rules_once(&[AllowlistRuleRecord {
            rule_id: "DEF-NET-BROWSER-CHROME".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: r"*\chrome.exe".to_string(),
            sha256: None,
            signer_subject: Some("Google LLC".to_string()),
            root_thumbprint: None,
            allowed_target: None,
            created_at_ms: 1_732_000_000_000,
            created_by: "system-default".to_string(),
        }])
        .expect("seed browser rule");

    let defense = Arc::new(RecordingDefense::new());
    let inspector = Arc::new(CountingInspector::new("c".repeat(64)));
    let engine = start_stopped_engine(
        store,
        DaemonConfig {
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::PreemptiveOnly,
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::clone(&inspector) as Arc<dyn crate::engine::BinaryInspector>,
    )
    .await;

    let app_id = ProcessIdentity::new(64001, 400_001);
    send_process_start(&engine, app_id, r"C:\Apps\unrelated_app.exe");
    let now_ms = current_unix_ms();

    for i in 0..5u16 {
        let _ = engine.process_event_with_lane(
            &SensorEvent::NetworkConnect {
                pid: app_id.pid,
                protocol: 6,
                dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                dst_port: 443 + i,
                domain_hint: None,
                timestamp_ms: now_ms + i64::from(i),
            },
            EventLane::HighPriority,
        );
    }

    assert_eq!(
        inspector.calls(),
        1,
        "ANALYSIS_0001: BinaryInspector must run only once when no persisted rule matches exe_path"
    );

    // Grant AllowOnce on the NET_OUTBOUND alert and confirm subsequent connects through the
    // real event-ingestion path (`process_event_with_lane` -> `events.rs` -> SQLite
    // `network_events`) skip BinaryInspector while persisting `"ALLOWED"` (`PRRT_kwDOVyjVyM657t_9`).
    let alerts = engine.store.list_alerts(None, 10).expect("list alerts");
    assert_eq!(alerts.len(), 1);
    let net_alert = alerts
        .iter()
        .find(|a| a.source_layer == "LAYER_3_NETWORK")
        .expect("outbound alert exists");
    engine
        .resolve_alert(&net_alert.alert_id, ledr_proto::AlertDecision::AllowOnce)
        .expect("AllowOnce");
    let calls_after_resolve = inspector.calls();
    assert_eq!(
        calls_after_resolve, 1,
        "AllowOnce resolution must not re-run BinaryInspector when sha256 is already recorded"
    );
    let allow_connect_event = SensorEvent::NetworkConnect {
        pid: app_id.pid,
        protocol: 6,
        dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        dst_port: 8443,
        domain_hint: None,
        timestamp_ms: now_ms + 100,
    };
    let _ = engine.process_event_with_lane(&allow_connect_event, EventLane::HighPriority);
    engine
        .store
        .flush_batch()
        .expect("flush network events batch");

    let snap = engine
        .store
        .query_flight_recorder(20, Some(&app_id.instance_id()))
        .expect("query flight recorder");
    let initial_row = snap
        .network_events
        .iter()
        .find(|ev| ev.dst_port == 443)
        .expect("initial connect event must be persisted in network_events");
    assert_eq!(
        initial_row.action, "ALERTED",
        "initial unknown connect in PreemptiveOnly mode must persist ALERTED"
    );
    let allowed_row = snap
        .network_events
        .iter()
        .find(|ev| ev.dst_port == 8443)
        .expect("AllowOnce connect event must be persisted in network_events");
    assert_eq!(
        allowed_row.action, "ALLOWED",
        "ANALYSIS_0001: real event ingestion path must persist ALLOWED for AllowOnce-granted process"
    );
    let dedup_count = snap
        .network_events
        .iter()
        .filter(|ev| (444..=447).contains(&ev.dst_port) && ev.action == "DEDUP_SUPPRESSED")
        .count();
    assert_eq!(
        dedup_count, 4,
        "pre-AllowOnce burst connects must persist DEDUP_SUPPRESSED"
    );
    assert_eq!(
        engine.store.list_alerts(None, 10).expect("list alerts").len(),
        1,
        "AllowOnce connect must not emit a duplicate alert"
    );
    assert_eq!(
        inspector.calls(),
        calls_after_resolve,
        "ANALYSIS_0001: AllowOnce fast path must still skip BinaryInspector when no rule matches exe_path"
    );
}

#[tokio::test]
async fn pr21_analysis_0002_audit_mode_preserves_has_domain_rules_for_dns_priority() {
    let store = LedrStore::open_in_memory().expect("in-memory store");
    store
        .upsert_rule(&AllowlistRuleRecord {
            rule_id: "AUDIT-DOM-1".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: r"C:\Apps\audit_app.exe".to_string(),
            sha256: None,
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("blocked.audit.example".to_string()),
            created_at_ms: 1_732_000_000_000,
            created_by: "test".to_string(),
        })
        .expect("insert domain rule");

    let defense = Arc::new(RecordingDefense::new());
    let engine = start_stopped_engine(
        store.clone(),
        DaemonConfig {
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::Audit,
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(FixedShaInspector("d".repeat(64))),
    )
    .await;

    let report = engine.deploy_persisted_network_rules();
    assert_eq!(report.applied, 0);
    assert!(defense.wfp_blocks_added().is_empty());
    assert!(
        engine.outbound_classifier.has_domain_rules(),
        "ANALYSIS_0002: Audit mode must keep has_domain_rules=true when domain rules exist"
    );

    store.delete_rule("AUDIT-DOM-1").expect("delete domain rule");
    let _ = engine.deploy_persisted_network_rules();
    assert!(
        !engine.outbound_classifier.has_domain_rules(),
        "ANALYSIS_0002: has_domain_rules must clear once domain rules are removed"
    );
}

#[test]
fn pr21_analysis_0003_shutdown_resumes_and_checkpoints_within_budget_before_nrd_detach() {
    use super::NrdThreadHandle;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    let tmp_dir = std::env::temp_dir().join(format!(
        "ledr-pr21-a03-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&tmp_dir).expect("create tmp dir");
    let db_path = tmp_dir.join("ledr.db");
    let wal_path = tmp_dir.join("ledr.db-wal");

    let (release_tx, release_rx) = mpsc::channel::<()>();
    let target = ProcessIdentity::new(65001, 500_001);
    let defense = Arc::new(RecordingDefense::new());

    {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build rt");

        rt.block_on(async {
            let store = LedrStore::open(&db_path).expect("open file store");
            store
                .record_alert(&AlertRecord {
                    alert_id: "alert-nrd-shutdown".to_string(),
                    timestamp_ms: 1_732_000_000_000,
                    severity: AlertSeverity::High,
                    source_layer: "LAYER_1_CANARY".to_string(),
                    rule_id: "LEDR-CANARY-COOKIE_DB".to_string(),
                    title: "Suspended before wedged NRD shutdown".to_string(),
                    process_instance_id: Some(target.instance_id()),
                    process_suspended: true,
                    status: AlertStatus::Pending,
                    context_json: "{}".to_string(),
                    resolved_at_ms: None,
                })
                .expect("seed alert");

            let engine = DaemonEngine::start_with_dependencies(
                store.clone(),
                SigmaEngine::default(),
                EarlyPruner::default(),
                DaemonConfig {
                    shutdown_flush_timeout_ms: 250,
                    resume_suspended_on_shutdown: true,
                    outbound_firewall_enabled: false,
                    ..DaemonConfig::default()
                },
                Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
                Arc::new(StubNotifier),
                Arc::new(FixedShaInspector("e".repeat(64))),
            );

            // Attach a wedged NRD thread that blocks beyond the 250 ms budget.
            let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
            let join_handle = std::thread::Builder::new()
                .name("ledr-pr21-wedged-nrd".to_string())
                .spawn(move || {
                    let _ = release_rx.recv();
                    let _ = done_tx.send(());
                })
                .expect("spawn wedged nrd");
            *engine
                .nrd_thread_handle
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = Some(NrdThreadHandle {
                join_handle,
                done_rx,
            });

            let started = Instant::now();
            engine.shutdown_and_flush().await.expect("shutdown");
            let elapsed = started.elapsed();
            assert!(
                elapsed >= Duration::from_millis(200) && elapsed < Duration::from_millis(480),
                "ANALYSIS_0003: shutdown with 250 ms budget and wedged NRD must respect budget window (< 2x budget, took {elapsed:?})"
            );

            assert!(
                defense.resumed().contains(&target),
                "ANALYSIS_0003: suspended process must be resumed before NRD wait/detach"
            );
            let alert = store
                .get_alert("alert-nrd-shutdown")
                .expect("get alert")
                .expect("alert exists");
            assert!(
                !alert.process_suspended,
                "ANALYSIS_0003: SQLite suspension state must be cleared before checkpoint_truncate"
            );
            let wal_len_after = std::fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0);
            assert_eq!(
                wal_len_after, 0,
                "ANALYSIS_0003: WAL must be truncated to 0 bytes after shutdown resume DB updates"
            );
        });
    }

    let _ = release_tx.send(());
    let _ = std::fs::remove_dir_all(&tmp_dir);
}

struct SlowResumeDefense {
    per_call_delay: std::time::Duration,
    resumed: Mutex<Vec<ProcessIdentity>>,
    last_resume_finished_at: Mutex<Option<std::time::Instant>>,
}

impl SlowResumeDefense {
    fn new(per_call_delay: std::time::Duration) -> Self {
        Self {
            per_call_delay,
            resumed: Mutex::new(Vec::new()),
            last_resume_finished_at: Mutex::new(None),
        }
    }

    fn resumed(&self) -> Vec<ProcessIdentity> {
        self.resumed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn last_resume_finished_at(&self) -> Option<std::time::Instant> {
        *self
            .last_resume_finished_at
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }
}

impl ActiveDefenseController for SlowResumeDefense {
    fn suspend_process(&self, _target: &ProcessIdentity, _include_children: bool) -> Result<(), String> {
        Ok(())
    }

    fn resume_process(&self, target: &ProcessIdentity) -> Result<(), String> {
        std::thread::sleep(self.per_call_delay);
        self.resumed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(*target);
        *self
            .last_resume_finished_at
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(std::time::Instant::now());
        Ok(())
    }

    fn terminate_process(
        &self,
        _target: &ProcessIdentity,
        _include_children: bool,
    ) -> Result<(), String> {
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

#[test]
fn pr21_v2_analysis_0003_shutdown_budget_caps_resume_loop_and_skips_nrd_wait_when_exhausted() {
    use super::NrdThreadHandle;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    let tmp_dir = std::env::temp_dir().join(format!(
        "ledr-pr21-v2-budget-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&tmp_dir).expect("create tmp dir");
    let db_path = tmp_dir.join("ledr.db");
    let wal_path = tmp_dir.join("ledr.db-wal");

    let (release_tx, release_rx) = mpsc::channel::<()>();
    let t1 = ProcessIdentity::new(66001, 600_001);
    let t2 = ProcessIdentity::new(66002, 600_002);
    let t3 = ProcessIdentity::new(66003, 600_003);
    // Each resume_process call takes 350 ms > 300 ms total shutdown budget, so after t1
    // finishes the shared deadline is already exhausted: t2/t3 must be skipped and the
    // wedged NRD thread must be detached immediately without starting a second 300 ms wait.
    let defense = Arc::new(SlowResumeDefense::new(Duration::from_millis(350)));

    {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build rt");

        rt.block_on(async {
            let store = LedrStore::open(&db_path).expect("open file store");
            for (idx, target) in [(1, t1), (2, t2), (3, t3)] {
                store
                    .record_alert(&AlertRecord {
                        alert_id: format!("alert-budget-{idx}"),
                        timestamp_ms: 1_732_000_000_000 + idx,
                        severity: AlertSeverity::High,
                        source_layer: "LAYER_1_CANARY".to_string(),
                        rule_id: "LEDR-CANARY-COOKIE_DB".to_string(),
                        title: format!("Suspended target {idx}"),
                        process_instance_id: Some(target.instance_id()),
                        process_suspended: true,
                        status: AlertStatus::Pending,
                        context_json: "{}".to_string(),
                        resolved_at_ms: None,
                    })
                    .expect("seed suspended alert");
            }

            let engine = DaemonEngine::start_with_dependencies(
                store.clone(),
                SigmaEngine::default(),
                EarlyPruner::default(),
                DaemonConfig {
                    shutdown_flush_timeout_ms: 300,
                    resume_suspended_on_shutdown: true,
                    outbound_firewall_enabled: false,
                    ..DaemonConfig::default()
                },
                Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
                Arc::new(StubNotifier),
                Arc::new(FixedShaInspector("f".repeat(64))),
            );

            // Also verify pre-expired deadline guard skips querying/resuming immediately.
            let pre_expired = tokio::time::Instant::now()
                .checked_sub(Duration::from_millis(1))
                .unwrap_or_else(tokio::time::Instant::now);
            assert!(
                !engine.resume_unresolved_suspended_processes_on_shutdown(pre_expired),
                "pre-expired shutdown deadline must skip resume pass without touching defense"
            );
            assert!(defense.resumed().is_empty());

            let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
            let join_handle = std::thread::Builder::new()
                .name("ledr-pr21-v2-wedged-nrd".to_string())
                .spawn(move || {
                    let _ = release_rx.recv();
                    let _ = done_tx.send(());
                })
                .expect("spawn wedged nrd");
            *engine
                .nrd_thread_handle
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = Some(NrdThreadHandle {
                join_handle,
                done_rx,
            });

            let started = Instant::now();
            engine.shutdown_and_flush().await.expect("shutdown");
            let finished_at = Instant::now();
            let elapsed = finished_at.saturating_duration_since(started);

            // Deterministic assertion: only t1 ran before the shared 300 ms budget expired.
            assert_eq!(
                defense.resumed(),
                vec![t1],
                "shutdown resume loop must stop once shared budget is exhausted"
            );
            // Measure strictly post-resume duration (< 250 ms, strictly below the 300 ms budget)
            // so any regression that starts a second full NRD timeout wait is guaranteed to fail.
            let after_resume_elapsed = finished_at.saturating_duration_since(
                defense
                    .last_resume_finished_at()
                    .expect("t1 resume timestamp recorded"),
            );
            assert!(
                after_resume_elapsed < Duration::from_millis(250),
                "post-resume checkpoint + immediate NRD detach must not wait a second 300 ms budget (post-resume took {after_resume_elapsed:?}, total {elapsed:?})"
            );
            assert!(
                elapsed < Duration::from_millis(620),
                "total shutdown must stay strictly below resume_delay + second_budget (took {elapsed:?})"
            );

            // SQLite reflects exact partial progress: t1 cleared, t2 & t3 preserved as suspended.
            assert!(
                !store.get_alert("alert-budget-1").unwrap().unwrap().process_suspended,
                "t1 must be cleared in SQLite after confirmed resume"
            );
            assert!(
                store.get_alert("alert-budget-2").unwrap().unwrap().process_suspended,
                "skipped t2 must remain process_suspended=true in SQLite"
            );
            assert!(
                store.get_alert("alert-budget-3").unwrap().unwrap().process_suspended,
                "skipped t3 must remain process_suspended=true in SQLite"
            );
            let wal_len_after = std::fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0);
            assert_eq!(
                wal_len_after, 0,
                "WAL must still be truncated to 0 bytes after budget-capped shutdown resume"
            );
        });
    }

    let _ = release_tx.send(());
    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[tokio::test]
async fn pr21_v2_bug_0002_allow_decisions_resume_leftover_children_after_partial_shutdown() {
    let store = LedrStore::open_in_memory().expect("in-memory store");
    let parent_once = ProcessIdentity::new(67001, 700_001);
    // Use current live PID so ProcessLiveness reports Running when resume fails.
    let leftover_child_once = ProcessIdentity::new(std::process::id(), 700_002);

    // Part A: Shutdown resumes parent_once but fails leftover_child_once, leaving
    // process_suspended=false with suspended_children=[leftover_child_once].
    store
        .record_alert(&AlertRecord {
            alert_id: "alert-partial-once".to_string(),
            timestamp_ms: 1_732_000_000_000,
            severity: AlertSeverity::Critical,
            source_layer: "LAYER_1_CANARY".to_string(),
            rule_id: "LEDR-CANARY-HONEYPOT".to_string(),
            title: "Honeypot tree partially resumed on shutdown".to_string(),
            process_instance_id: Some(parent_once.instance_id()),
            process_suspended: true,
            status: AlertStatus::Pending,
            context_json: serde_json::json!({
                "exe_path": r"C:\Temp\partial_once.exe",
                "suspended_children": [leftover_child_once.instance_id()]
            })
            .to_string(),
            resolved_at_ms: None,
        })
        .expect("seed partial once alert");

    let shutdown_defense = Arc::new(PartialResumeDefense::new(leftover_child_once));
    let engine_before_restart = DaemonEngine::start_with_dependencies(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            resume_suspended_on_shutdown: true,
            ..DaemonConfig::default()
        },
        Arc::clone(&shutdown_defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(StubNotifier),
        Arc::new(FixedShaInspector("a".repeat(64))),
    );
    engine_before_restart
        .shutdown_and_flush()
        .await
        .expect("shutdown with partial resume");
    assert_eq!(shutdown_defense.resumed(), vec![parent_once]);

    let after_shutdown = store
        .get_alert("alert-partial-once")
        .unwrap()
        .expect("alert exists");
    assert!(!after_shutdown.process_suspended);

    // After restart, if child resume still fails on AllowOnce, the alert must stay unresolved.
    let failing_after_restart = Arc::new(PartialResumeDefense::new(leftover_child_once));
    let engine_fail = start_stopped_engine(
        store.clone(),
        DaemonConfig::default(),
        Arc::clone(&failing_after_restart) as Arc<dyn ActiveDefenseController>,
        Arc::new(FixedShaInspector("a".repeat(64))),
    )
    .await;
    assert!(
        engine_fail
            .resolve_alert("alert-partial-once", ledr_proto::AlertDecision::AllowOnce)
            .is_err(),
        "AllowOnce must fail and keep alert unresolved when leftover child fails to resume"
    );
    assert_eq!(
        store.get_alert("alert-partial-once").unwrap().unwrap().status,
        AlertStatus::Pending
    );

    // Once child resume succeeds, AllowOnce must resume ONLY the leftover child (not the
    // already-resumed parent) and resolve the alert.
    let ok_defense_once = Arc::new(RecordingDefense::new());
    let engine_ok_once = start_stopped_engine(
        store.clone(),
        DaemonConfig::default(),
        Arc::clone(&ok_defense_once) as Arc<dyn ActiveDefenseController>,
        Arc::new(FixedShaInspector("a".repeat(64))),
    )
    .await;
    let resolved_once = engine_ok_once
        .resolve_alert("alert-partial-once", ledr_proto::AlertDecision::AllowOnce)
        .expect("AllowOnce must resume leftover child");
    assert_eq!(resolved_once.status, AlertStatus::ApprovedOnce);
    assert_eq!(
        ok_defense_once.resumed(),
        vec![leftover_child_once],
        "AllowOnce must resume leftover suspended child without re-resuming parent"
    );

    // Part B: AllowPermanent on a parent-resumed / child-frozen alert must roll back the
    // saved rule when child resume fails, and resume the child when it succeeds.
    let parent_perm = ProcessIdentity::new(67010, 700_010);
    let leftover_child_perm = ProcessIdentity::new(std::process::id(), 700_011);
    store
        .record_alert(&AlertRecord {
            alert_id: "alert-partial-perm".to_string(),
            timestamp_ms: 1_732_000_010_000,
            severity: AlertSeverity::Critical,
            source_layer: "LAYER_1_CANARY".to_string(),
            rule_id: "LEDR-CANARY-HONEYPOT".to_string(),
            title: "Honeypot tree partially resumed before AllowPermanent".to_string(),
            process_instance_id: Some(parent_perm.instance_id()),
            process_suspended: false,
            status: AlertStatus::Pending,
            context_json: serde_json::json!({
                "exe_path": r"C:\Temp\partial_perm.exe",
                "suspended_children": [leftover_child_perm.instance_id()]
            })
            .to_string(),
            resolved_at_ms: None,
        })
        .expect("seed partial perm alert");

    let fail_perm_defense = Arc::new(PartialResumeDefense::new(leftover_child_perm));
    let engine_fail_perm = start_stopped_engine(
        store.clone(),
        DaemonConfig::default(),
        Arc::clone(&fail_perm_defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(FixedShaInspector("b".repeat(64))),
    )
    .await;
    assert!(
        engine_fail_perm
            .resolve_alert(
                "alert-partial-perm",
                ledr_proto::AlertDecision::AllowPermanent {
                    use_signer_if_available: false,
                    allow_dest: None,
                },
            )
            .is_err(),
        "AllowPermanent must fail when leftover child fails to resume"
    );
    assert!(
        store.list_rules(None).unwrap().is_empty(),
        "AllowPermanent must roll back saved allowlist rule when leftover child resume fails"
    );
    assert_eq!(
        store.get_alert("alert-partial-perm").unwrap().unwrap().status,
        AlertStatus::Pending
    );

    let ok_defense_perm = Arc::new(RecordingDefense::new());
    let engine_ok_perm = start_stopped_engine(
        store.clone(),
        DaemonConfig::default(),
        Arc::clone(&ok_defense_perm) as Arc<dyn ActiveDefenseController>,
        Arc::new(FixedShaInspector("b".repeat(64))),
    )
    .await;
    let resolved_perm = engine_ok_perm
        .resolve_alert(
            "alert-partial-perm",
            ledr_proto::AlertDecision::AllowPermanent {
                use_signer_if_available: false,
                allow_dest: None,
            },
        )
        .expect("AllowPermanent must resume leftover child");
    assert_eq!(resolved_perm.status, AlertStatus::ApprovedRule);
    assert_eq!(ok_defense_perm.resumed(), vec![leftover_child_perm]);
    assert_eq!(store.list_rules(None).unwrap().len(), 1);

    // Part C: Another unresolved alert still holding the same child must keep it frozen until
    // both alerts are resolved.
    let parent_sib = ProcessIdentity::new(67020, 700_020);
    let shared_child = ProcessIdentity::new(67021, 700_021);
    for id in ["alert-sib-child-1", "alert-sib-child-2"] {
        store
            .record_alert(&AlertRecord {
                alert_id: id.to_string(),
                timestamp_ms: 1_732_000_020_000,
                severity: AlertSeverity::Critical,
                source_layer: "LAYER_1_CANARY".to_string(),
                rule_id: "LEDR-CANARY-HONEYPOT".to_string(),
                title: "Sibling child containment".to_string(),
                process_instance_id: Some(parent_sib.instance_id()),
                process_suspended: false,
                status: AlertStatus::Pending,
                context_json: serde_json::json!({
                    "exe_path": r"C:\Temp\partial_sib.exe",
                    "suspended_children": [shared_child.instance_id()]
                })
                .to_string(),
                resolved_at_ms: None,
            })
            .expect("seed sibling child alert");
    }

    let sib_defense = Arc::new(RecordingDefense::new());
    let engine_sib = start_stopped_engine(
        store.clone(),
        DaemonConfig::default(),
        Arc::clone(&sib_defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(FixedShaInspector("c".repeat(64))),
    )
    .await;
    engine_sib
        .resolve_alert("alert-sib-child-1", ledr_proto::AlertDecision::AllowOnce)
        .expect("resolve first sibling alert");
    assert!(
        sib_defense.resumed().is_empty(),
        "shared child must remain frozen while sibling unresolved alert still holds it"
    );
    engine_sib
        .resolve_alert("alert-sib-child-2", ledr_proto::AlertDecision::AllowOnce)
        .expect("resolve second sibling alert");
    assert_eq!(
        sib_defense.resumed(),
        vec![shared_child],
        "shared child must be resumed once the last unresolved alert holding it is allowed"
    );
}

#[tokio::test]
async fn pr21_v2_bug_0002_deferred_sibling_children_survive_shutdown_and_partial_resume() {
    let store = LedrStore::open_in_memory().expect("in-memory store");

    // Scenario A: Alert A (parent + child C1) is allowed FIRST while sibling Alert B (same
    // parent, no recorded children yet) stays pending. Resolving A defers resuming parent/C1
    // AND transfers C1 onto Alert B so a subsequent shutdown resumes BOTH parent and C1.
    let parent_a = ProcessIdentity::new(67101, 710_001);
    let child_a = ProcessIdentity::new(67102, 710_002);
    store
        .record_alert(&AlertRecord {
            alert_id: "alert-xfer-a1".to_string(),
            timestamp_ms: 1_732_000_100_000,
            severity: AlertSeverity::Critical,
            source_layer: "LAYER_1_CANARY".to_string(),
            rule_id: "LEDR-CANARY-HONEYPOT".to_string(),
            title: "Honeypot alert with suspended child".to_string(),
            process_instance_id: Some(parent_a.instance_id()),
            process_suspended: true,
            status: AlertStatus::Pending,
            context_json: serde_json::json!({
                "exe_path": r"C:\Temp\xfer_a.exe",
                "suspended_children": [child_a.instance_id()]
            })
            .to_string(),
            resolved_at_ms: None,
        })
        .expect("seed alert-xfer-a1");
    store
        .record_alert(&AlertRecord {
            alert_id: "alert-xfer-a2".to_string(),
            timestamp_ms: 1_732_000_100_010,
            severity: AlertSeverity::High,
            source_layer: "LAYER_1_CANARY".to_string(),
            rule_id: "LEDR-CANARY-COOKIE_DB".to_string(),
            title: "CookieDb sibling holding same parent".to_string(),
            process_instance_id: Some(parent_a.instance_id()),
            process_suspended: true,
            status: AlertStatus::Pending,
            context_json: serde_json::json!({
                "exe_path": r"C:\Temp\xfer_a.exe"
            })
            .to_string(),
            resolved_at_ms: None,
        })
        .expect("seed alert-xfer-a2");

    let defense_a = Arc::new(RecordingDefense::new());
    let engine_a = DaemonEngine::start_with_dependencies(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            resume_suspended_on_shutdown: true,
            ..DaemonConfig::default()
        },
        Arc::clone(&defense_a) as Arc<dyn ActiveDefenseController>,
        Arc::new(StubNotifier),
        Arc::new(FixedShaInspector("a".repeat(64))),
    );
    engine_a
        .resolve_alert("alert-xfer-a1", ledr_proto::AlertDecision::AllowOnce)
        .expect("resolve alert-xfer-a1 while sibling holds parent");
    assert!(
        defense_a.resumed().is_empty(),
        "parent and child must stay suspended while sibling alert-xfer-a2 holds parent"
    );
    // Verify child_a was transferred onto surviving unresolved sibling alert-xfer-a2.
    let sib_a2 = store.get_alert("alert-xfer-a2").unwrap().expect("a2 exists");
    let sib_a2_ctx: serde_json::Value = serde_json::from_str(&sib_a2.context_json).unwrap();
    assert_eq!(
        sib_a2_ctx["suspended_children"],
        serde_json::json!([child_a.instance_id()]),
        "deferred child must be transferred onto unresolved parent-holding sibling"
    );

    // Now shut down with resume_suspended_on_shutdown=true: BOTH parent_a and child_a must resume!
    engine_a
        .shutdown_and_flush()
        .await
        .expect("shutdown must resume both parent and transferred child");
    assert_eq!(
        defense_a.resumed(),
        vec![parent_a, child_a],
        "shutdown after sibling deferral must resume both parent and transferred child"
    );

    // Scenario B: Same deferral, then PARTIAL shutdown resumes parent_b but fails live child_b.
    // After restart, AllowOnce on the surviving sibling (now process_suspended=false) must STILL
    // resume child_b instead of orphaning it frozen!
    let parent_b = ProcessIdentity::new(67111, 710_011);
    let child_b = ProcessIdentity::new(std::process::id(), 710_012);
    store
        .record_alert(&AlertRecord {
            alert_id: "alert-xfer-b1".to_string(),
            timestamp_ms: 1_732_000_200_000,
            severity: AlertSeverity::Critical,
            source_layer: "LAYER_1_CANARY".to_string(),
            rule_id: "LEDR-CANARY-HONEYPOT".to_string(),
            title: "Honeypot alert deferred before partial shutdown".to_string(),
            process_instance_id: Some(parent_b.instance_id()),
            process_suspended: true,
            status: AlertStatus::Pending,
            context_json: serde_json::json!({
                "exe_path": r"C:\Temp\xfer_b.exe",
                "suspended_children": [child_b.instance_id()]
            })
            .to_string(),
            resolved_at_ms: None,
        })
        .expect("seed alert-xfer-b1");
    store
        .record_alert(&AlertRecord {
            alert_id: "alert-xfer-b2".to_string(),
            timestamp_ms: 1_732_000_200_010,
            severity: AlertSeverity::High,
            source_layer: "LAYER_1_CANARY".to_string(),
            rule_id: "LEDR-CANARY-COOKIE_DB".to_string(),
            title: "CookieDb sibling surviving partial shutdown".to_string(),
            process_instance_id: Some(parent_b.instance_id()),
            process_suspended: true,
            status: AlertStatus::Pending,
            context_json: serde_json::json!({
                "exe_path": r"C:\Temp\xfer_b.exe"
            })
            .to_string(),
            resolved_at_ms: None,
        })
        .expect("seed alert-xfer-b2");

    let partial_b_defense = Arc::new(PartialResumeDefense::new(child_b));
    let engine_b1 = DaemonEngine::start_with_dependencies(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            resume_suspended_on_shutdown: true,
            ..DaemonConfig::default()
        },
        Arc::clone(&partial_b_defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(StubNotifier),
        Arc::new(FixedShaInspector("b".repeat(64))),
    );
    engine_b1
        .resolve_alert("alert-xfer-b1", ledr_proto::AlertDecision::AllowOnce)
        .expect("resolve b1 first");
    assert!(partial_b_defense.resumed().is_empty());

    engine_b1
        .shutdown_and_flush()
        .await
        .expect("partial shutdown");
    assert_eq!(partial_b_defense.resumed(), vec![parent_b]);

    let sib_b2_after_shutdown = store.get_alert("alert-xfer-b2").unwrap().unwrap();
    assert!(
        !sib_b2_after_shutdown.process_suspended,
        "parent_b was resumed during shutdown"
    );
    let sib_b2_ctx: serde_json::Value =
        serde_json::from_str(&sib_b2_after_shutdown.context_json).unwrap();
    assert_eq!(
        sib_b2_ctx["suspended_children"],
        serde_json::json!([child_b.instance_id()]),
        "failed live child_b must remain on alert-xfer-b2 after partial shutdown"
    );

    // Post-restart AllowOnce on alert-xfer-b2 must resume child_b!
    let restart_b_defense = Arc::new(RecordingDefense::new());
    let engine_b2 = start_stopped_engine(
        store.clone(),
        DaemonConfig::default(),
        Arc::clone(&restart_b_defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(FixedShaInspector("b".repeat(64))),
    )
    .await;
    let resolved_b2 = engine_b2
        .resolve_alert("alert-xfer-b2", ledr_proto::AlertDecision::AllowOnce)
        .expect("post-restart AllowOnce on surviving sibling must resume leftover child");
    assert_eq!(resolved_b2.status, AlertStatus::ApprovedOnce);
    assert_eq!(
        restart_b_defense.resumed(),
        vec![child_b],
        "surviving sibling must resume transferred child_b even after partial shutdown cleared process_suspended"
    );
}

struct MapLiveProcessInspector {
    entries: Mutex<std::collections::HashMap<u32, ledr_sensor_win::etw::LiveProcessInfo>>,
    calls: AtomicU64,
}

impl MapLiveProcessInspector {
    fn new(
        entries: impl IntoIterator<Item = (u32, ledr_sensor_win::etw::LiveProcessInfo)>,
    ) -> Self {
        Self {
            entries: Mutex::new(entries.into_iter().collect()),
            calls: AtomicU64::new(0),
        }
    }

    fn set(&self, pid: u32, info: ledr_sensor_win::etw::LiveProcessInfo) {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(pid, info);
    }

    fn calls(&self) -> u64 {
        self.calls.load(Ordering::Relaxed)
    }
}

impl crate::engine::LiveProcessInspector for MapLiveProcessInspector {
    fn inspect_live_process(&self, pid: u32) -> Option<ledr_sensor_win::etw::LiveProcessInfo> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&pid)
            .cloned()
    }
}

async fn start_stopped_engine_with_live_inspector(
    store: LedrStore,
    config: DaemonConfig,
    defense: Arc<dyn ActiveDefenseController>,
    inspector: Arc<dyn crate::engine::BinaryInspector>,
    live_inspector: Arc<dyn crate::engine::LiveProcessInspector>,
) -> Arc<DaemonEngine> {
    let engine = DaemonEngine::start_with_all_dependencies(
        store,
        SigmaEngine::default(),
        EarlyPruner::default(),
        config,
        defense,
        Arc::new(StubNotifier),
        inspector,
        live_inspector,
    );
    if let Some(h) = engine.worker_handle.lock().await.take() {
        h.abort();
        let _ = h.await;
    }
    engine
}

#[tokio::test]
async fn pr21_v2_ci_0001_canary_backfill_rejects_low_bit_pid_alias_and_missing_live_exe() {
    let store = LedrStore::open_in_memory().expect("in-memory store");
    let defense = Arc::new(RecordingDefense::new());
    let inspector = Arc::new(FixedShaInspector("9".repeat(64)));

    let engine = start_stopped_engine(
        store.clone(),
        DaemonConfig::default(),
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        inspector,
    )
    .await;

    let live_pid = std::process::id();
    let now_ms = current_unix_ms();

    // Part A: Windows OpenProcess masks off the low 2 bits (`pid & !3`), so `live_pid + 1..=3`
    // would previously open `live_pid` and falsely backfill & suspend an unregistered synthetic PID
    // (the exact CI failure mode hit by `daemon_p2_10` when PID 7700 existed on the runner).
    for offset in 1..=3u32 {
        let alias_pid = live_pid.saturating_add(offset);
        let _ = engine.process_event_with_lane(
            &SensorEvent::CanaryFileAccess {
                pid: alias_pid,
                target_path: format!(r"C:\Users\alice\.ssh\id_rsa_{offset}"),
                category: CanaryCategory::SshKey,
                access_mask: 1,
                is_write_or_delete: false,
                timestamp_ms: now_ms + i64::from(offset),
            },
            EventLane::HighPriority,
        );
    }

    assert!(
        defense.suspended().is_empty(),
        "low-bit PID aliases of a live process must never be backfilled or suspended"
    );
    let alerts = store.list_alerts(None, 20).expect("list alerts");
    assert_eq!(alerts.len(), 3);
    assert!(alerts.iter().all(|a| !a.process_suspended));
    assert!(alerts.iter().all(|a| a.process_instance_id.is_none()));

    // Part B: Exercise the REAL `process_event_with_lane` pipeline with an injected
    // `LiveProcessInspector` when a multiple-of-4 synthetic PID already has a known `exe_path`
    // and `create_time_100ns == 0`: backfill must fail closed if live `exe_path` is `None` or blank.
    let store_b = LedrStore::open_in_memory().expect("in-memory store B");
    let defense_b = Arc::new(RecordingDefense::new());
    let live_create_100ns = 116_444_736_000_000_000u64 + ((now_ms as u64).saturating_sub(5_000)) * 10_000;
    let live_inspector = Arc::new(MapLiveProcessInspector::new([
        (
            7700,
            ledr_sensor_win::etw::LiveProcessInfo {
                create_time_100ns: live_create_100ns,
                exe_path: None,
                command_line: None,
                package_family_name: None,
                package_sid: None,
            },
        ),
        (
            7704,
            ledr_sensor_win::etw::LiveProcessInfo {
                create_time_100ns: live_create_100ns,
                exe_path: Some("   ".to_string()),
                command_line: None,
                package_family_name: None,
                package_sid: None,
            },
        ),
    ]));
    let engine_b = start_stopped_engine_with_live_inspector(
        store_b.clone(),
        DaemonConfig::default(),
        Arc::clone(&defense_b) as Arc<dyn ActiveDefenseController>,
        Arc::new(FixedShaInspector("9".repeat(64))),
        Arc::clone(&live_inspector) as Arc<dyn crate::engine::LiveProcessInspector>,
    )
    .await;

    for (pid, target) in [
        (7700u32, r"C:\Users\alice\.aws\credentials_none"),
        (7704u32, r"C:\Users\alice\.aws\credentials_blank"),
    ] {
        let zero_ident = ProcessIdentity::new(pid, 0);
        send_process_start(&engine_b, zero_ident, r"C:\Temp\zero_ts.exe");
        let _ = engine_b.process_event_with_lane(
            &SensorEvent::CanaryFileAccess {
                pid,
                target_path: target.to_string(),
                category: CanaryCategory::CloudCredential,
                access_mask: 1,
                is_write_or_delete: false,
                timestamp_ms: now_ms + 100,
            },
            EventLane::HighPriority,
        );
    }

    assert_eq!(live_inspector.calls(), 2);
    assert!(
        defense_b.suspended().is_empty(),
        "real CanaryFileAccess pipeline must fail closed and never suspend when live exe_path is None or whitespace"
    );
    let alerts_b = store_b.list_alerts(None, 10).expect("list alerts B");
    assert_eq!(alerts_b.len(), 2);
    assert!(alerts_b.iter().all(|a| !a.process_suspended));
    assert!(alerts_b
        .iter()
        .all(|a| a.process_instance_id.as_deref().is_some_and(|id| id.ends_with(":0"))));
}

#[tokio::test]
async fn pr21_v2_ci_0002_canary_backfill_preserves_created_at_ppid_and_skips_noop_writes() {
    let store = LedrStore::open_in_memory().expect("in-memory store");
    let defense = Arc::new(RecordingDefense::new());
    let now_ms = current_unix_ms();
    let created_ms = now_ms - 5_000;
    let created_100ns = 116_444_736_000_000_000u64 + (created_ms as u64) * 10_000;

    let live_inspector = Arc::new(MapLiveProcessInspector::new([
        (
            4400,
            ledr_sensor_win::etw::LiveProcessInfo {
                create_time_100ns: created_100ns,
                exe_path: Some(r"C:\Temp\unregistered_stealer.exe".to_string()),
                command_line: Some("unregistered_stealer.exe --dump".to_string()),
                package_family_name: None,
                package_sid: None,
            },
        ),
        (
            4404,
            ledr_sensor_win::etw::LiveProcessInfo {
                create_time_100ns: created_100ns,
                exe_path: Some(r"C:\Temp\zero_ts_upgraded.exe".to_string()),
                command_line: None,
                package_family_name: None,
                package_sid: None,
            },
        ),
        (
            4408,
            ledr_sensor_win::etw::LiveProcessInfo {
                create_time_100ns: created_100ns,
                exe_path: None,
                command_line: None,
                package_family_name: None,
                package_sid: None,
            },
        ),
    ]));

    let engine = start_stopped_engine_with_live_inspector(
        store.clone(),
        DaemonConfig::default(),
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(FixedShaInspector("8".repeat(64))),
        Arc::clone(&live_inspector) as Arc<dyn crate::engine::LiveProcessInspector>,
    )
    .await;

    // 1. Unregistered multiple-of-4 PID 4400 backfills with actual `created_ms` (not `event_ts_ms`),
    //    so `lookup_by_pid_at` resolves timestamps between process creation and the canary event.
    let _ = engine.process_event_with_lane(
        &SensorEvent::CanaryFileAccess {
            pid: 4400,
            target_path: r"C:\Users\alice\.ssh\id_rsa".to_string(),
            category: CanaryCategory::SshKey,
            access_mask: 1,
            is_write_or_delete: false,
            timestamp_ms: now_ms,
        },
        EventLane::HighPriority,
    );
    let id_4400 = ProcessIdentity::new(4400, created_100ns);
    assert_eq!(defense.suspended(), vec![id_4400]);
    {
        let table = engine.process_table.lock().unwrap_or_else(|e| e.into_inner());
        let mid_ts = created_ms + 2_000;
        let resolved = table
            .lookup_by_pid_at(4400, mid_ts)
            .expect("backfilled entry must use live created_at_ms so earlier events resolve");
        assert_eq!(resolved.identity, id_4400);
        assert_eq!(resolved.created_at_ms, created_ms);
    }
    // Late real ETW ProcessStart arriving with parent_pid=1234 upgrades ppid in table & store.
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: id_4400,
            parent_pid: 1234,
            exe_path: r"C:\Temp\unregistered_stealer.exe".to_string(),
            command_line: "unregistered_stealer.exe --dump".to_string(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    {
        let table = engine.process_table.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(
            table.get_by_instance_id(&id_4400.instance_id()).map(|e| e.ppid),
            Some(1234)
        );
    }

    // 2. Existing `(4404, 0)` placeholder (whose fallback created_at_ms is `now_ms > created_ms`)
    //    upgraded by matching live exe_path must become the ACTIVE entry (not inferred-exited!)
    //    and preserve its existing `ppid = 2222`.
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: ProcessIdentity::new(4404, 0),
            parent_pid: 2222,
            exe_path: r"C:\Temp\zero_ts_upgraded.exe".to_string(),
            command_line: "zero_ts_upgraded.exe".to_string(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    // Derive the canary event timestamp after registering the `(4404, 0)` placeholder so slow
    // test runners (>50 ms elapsed since `now_ms`) never place the canary event before the
    // placeholder's fallback `created_at_ms` (`ANALYSIS_0001`).
    let canary_ts_4404 = {
        let table = engine.process_table.lock().unwrap_or_else(|e| e.into_inner());
        let placeholder_created = table
            .lookup_by_pid(4404)
            .expect("placeholder 4404 must be registered")
            .created_at_ms;
        current_unix_ms().max(placeholder_created)
    };
    let _ = engine.process_event_with_lane(
        &SensorEvent::CanaryFileAccess {
            pid: 4404,
            target_path: r"C:\Users\alice\.aws\credentials".to_string(),
            category: CanaryCategory::CloudCredential,
            access_mask: 1,
            is_write_or_delete: false,
            timestamp_ms: canary_ts_4404,
        },
        EventLane::HighPriority,
    );
    let id_4404 = ProcessIdentity::new(4404, created_100ns);
    {
        let table = engine.process_table.lock().unwrap_or_else(|e| e.into_inner());
        let active = table
            .lookup_by_pid(4404)
            .expect("upgraded verified identity must be active");
        assert_eq!(active.identity, id_4404);
        assert_eq!(active.exited_at_ms, None, "verified backfill must not be marked exited");
        assert_eq!(active.ppid, 2222, "upgraded entry must preserve existing ppid");
    }

    // 3. Existing verified `(4408, created_100ns)` with `ppid = 3333` and empty `exe_path`:
    //    (a) no-op backfill (`live.exe_path == None`) must NOT overwrite ppid=3333 in SQLite;
    //    (b) subsequent backfill supplying `exe_path` must ALSO preserve ppid=3333 in SQLite.
    let id_4408 = ProcessIdentity::new(4408, created_100ns);
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: id_4408,
            parent_pid: 3333,
            exe_path: String::new(),
            command_line: String::new(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    let canary_ts_4408_noop = current_unix_ms().max(created_ms + 100);
    let _ = engine.process_event_with_lane(
        &SensorEvent::CanaryFileAccess {
            pid: 4408,
            target_path: r"C:\Users\alice\.env.noop".to_string(),
            category: CanaryCategory::EnvFile,
            access_mask: 1,
            is_write_or_delete: false,
            timestamp_ms: canary_ts_4408_noop,
        },
        EventLane::HighPriority,
    );
    store.flush_batch().expect("flush after noop backfill");
    let snap_noop = store
        .query_flight_recorder(10, Some(&id_4408.instance_id()))
        .expect("query after noop backfill");
    let row_noop = snap_noop
        .processes
        .iter()
        .find(|p| p.process_instance_id == id_4408.instance_id())
        .expect("4408 row exists");
    assert_eq!(row_noop.ppid, 3333, "no-op backfill must not clobber ppid in SQLite");
    assert_eq!(row_noop.exe_path, "");

    live_inspector.set(
        4408,
        ledr_sensor_win::etw::LiveProcessInfo {
            create_time_100ns: created_100ns,
            exe_path: Some(r"C:\Temp\enriched_4408.exe".to_string()),
            command_line: None,
            package_family_name: None,
            package_sid: None,
        },
    );
    let canary_ts_4408_enriched = current_unix_ms().max(canary_ts_4408_noop + 1);
    let _ = engine.process_event_with_lane(
        &SensorEvent::CanaryFileAccess {
            pid: 4408,
            target_path: r"C:\Users\alice\.env.enriched".to_string(),
            category: CanaryCategory::EnvFile,
            access_mask: 1,
            is_write_or_delete: false,
            timestamp_ms: canary_ts_4408_enriched,
        },
        EventLane::HighPriority,
    );
    store.flush_batch().expect("flush after enriched backfill");
    let snap_enriched = store
        .query_flight_recorder(10, Some(&id_4408.instance_id()))
        .expect("query after enriched backfill");
    let row_enriched = snap_enriched
        .processes
        .iter()
        .find(|p| p.process_instance_id == id_4408.instance_id())
        .expect("4408 row exists after enrichment");
    assert_eq!(
        row_enriched.ppid, 3333,
        "exe_path backfill must preserve existing ppid in SQLite"
    );
    assert_eq!(row_enriched.exe_path, r"C:\Temp\enriched_4408.exe");
}

#[tokio::test]
async fn pr21_v2_ci_0003_resolve_alert_refuses_low_bit_pid_alias_from_defense_guard() {
    let store = LedrStore::open_in_memory().expect("in-memory store");
    let real_defense = Arc::new(ledr_sensor_win::WindowsDefenseController::new());
    let engine = start_stopped_engine(
        store.clone(),
        DaemonConfig {
            outbound_firewall_enabled: false,
            ..DaemonConfig::default()
        },
        real_defense as Arc<dyn ActiveDefenseController>,
        Arc::new(FixedShaInspector("7".repeat(64))),
    )
    .await;

    let self_alias = ProcessIdentity::new(std::process::id().saturating_add(1), 133_800_000_000_000_000);
    let system_alias = ProcessIdentity::new(5, 133_800_000_000_000_000);

    for (alert_id, ident) in [("alias-self", self_alias), ("alias-system", system_alias)] {
        store
            .record_alert(&AlertRecord {
                alert_id: alert_id.to_string(),
                timestamp_ms: current_unix_ms(),
                severity: AlertSeverity::High,
                source_layer: "LAYER_1_CANARY".to_string(),
                rule_id: "LEDR-CANARY-SSH_KEY".to_string(),
                title: "Forged low-bit PID alias alert".to_string(),
                process_instance_id: Some(ident.instance_id()),
                process_suspended: true,
                status: AlertStatus::Pending,
                context_json: r#"{"exe_path":"C:\\Temp\\forged.exe"}"#.to_string(),
                resolved_at_ms: None,
            })
            .expect("seed aliased alert");

        let allow_err = engine
            .resolve_alert(alert_id, ledr_proto::AlertDecision::AllowOnce)
            .expect_err("AllowOnce must NOT swallow low-bit PID alias refusal as Gone");
        assert!(
            allow_err.contains("refusing to act on"),
            "expected policy refusal on AllowOnce for {alert_id}, got: {allow_err}"
        );
        let term_err = engine
            .resolve_alert(
                alert_id,
                ledr_proto::AlertDecision::TerminateAndBlock {
                    add_block_rule: false,
                },
            )
            .expect_err("TerminateAndBlock must NOT swallow low-bit PID alias refusal as Gone");
        assert!(
            term_err.contains("refusing to act on"),
            "expected policy refusal on TerminateAndBlock for {alert_id}, got: {term_err}"
        );
        assert_eq!(
            store.get_alert(alert_id).unwrap().unwrap().status,
            AlertStatus::Pending,
            "aliased alert {alert_id} must remain Pending after policy refusal"
        );
    }
}

#[tokio::test]
async fn pr23_bug_0001_superseded_zero_ts_placeholder_closed_in_sqlite_on_start_and_backfill() {
    let store = LedrStore::open_in_memory().expect("in-memory store");
    let defense = Arc::new(RecordingDefense::new());
    let now_ms = current_unix_ms();
    let real_created_ms = now_ms - 5_000;
    let real_created_100ns = 116_444_736_000_000_000u64 + (real_created_ms as u64) * 10_000;

    let live_inspector = Arc::new(MapLiveProcessInspector::new([(
        4604,
        ledr_sensor_win::etw::LiveProcessInfo {
            create_time_100ns: real_created_100ns,
            exe_path: Some(r"C:\Temp\backfill_4604.exe".to_string()),
            command_line: Some("backfill_4604.exe".to_string()),
            package_family_name: None,
            package_sid: None,
        },
    )]));

    let engine = start_stopped_engine_with_live_inspector(
        store.clone(),
        DaemonConfig {
            outbound_firewall_enabled: false,
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(FixedShaInspector("9".repeat(64))),
        Arc::clone(&live_inspector) as Arc<dyn crate::engine::LiveProcessInspector>,
    )
    .await;

    // Path A: startup snapshot records `4600:0` -> alert references `4600:0` -> late ETW
    // ProcessStart delivers real `4600:<real_ts>` (older than snapshot fallback time) ->
    // ProcessStop closes `4600:<real_ts>`. Neither row may stay running (`exited_at_ms IS NULL`),
    // and the placeholder must have `exited_at_ms >= created_at_ms` while preserving references.
    let placeholder_a = ProcessIdentity::new(4600, 0);
    let real_a = ProcessIdentity::new(4600, real_created_100ns);
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: placeholder_a,
            parent_pid: 4,
            exe_path: r"C:\Temp\late_etw_4600.exe".to_string(),
            command_line: String::new(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    store.flush_batch().expect("flush snapshot placeholder A");
    store
        .record_alert(&AlertRecord {
            alert_id: "alert-placeholder-4600".to_string(),
            timestamp_ms: now_ms,
            severity: AlertSeverity::Medium,
            source_layer: "LAYER_1_CANARY".to_string(),
            rule_id: "LEDR-TEST-PLACEHOLDER".to_string(),
            title: "Alert tied to snapshot placeholder".to_string(),
            process_instance_id: Some(placeholder_a.instance_id()),
            process_suspended: false,
            status: AlertStatus::Pending,
            context_json: "{}".to_string(),
            resolved_at_ms: None,
        })
        .expect("record alert referencing placeholder");

    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: real_a,
            parent_pid: 4,
            exe_path: r"C:\Temp\late_etw_4600.exe".to_string(),
            command_line: "late_etw_4600.exe --svc".to_string(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    let stop_ms = current_unix_ms() + 1_000;
    let stop_100ns = 116_444_736_000_000_000u64 + (stop_ms as u64) * 10_000;
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStop {
            pid: 4600,
            exit_time_100ns: stop_100ns,
            exit_code: 0,
        },
        EventLane::HighPriority,
    );
    store.flush_batch().expect("flush real start & stop A");

    let snap_a = store
        .query_flight_recorder(50, None)
        .expect("query flight recorder A");
    let ph_a_row = snap_a
        .processes
        .iter()
        .find(|p| p.process_instance_id == placeholder_a.instance_id())
        .expect("placeholder A row preserved for alert lineage");
    let real_a_row = snap_a
        .processes
        .iter()
        .find(|p| p.process_instance_id == real_a.instance_id())
        .expect("real A row exists");
    assert!(
        ph_a_row.exited_at_ms.is_some(),
        "superseded placeholder 4600:0 must not stay running in SQLite"
    );
    assert!(
        ph_a_row.exited_at_ms.unwrap() >= ph_a_row.created_at_ms,
        "placeholder exited_at_ms ({:?}) must not precede created_at_ms ({})",
        ph_a_row.exited_at_ms,
        ph_a_row.created_at_ms
    );
    assert_eq!(real_a_row.exited_at_ms, Some(stop_ms));
    assert_eq!(
        snap_a
            .processes
            .iter()
            .filter(|p| p.pid == 4600 && p.exited_at_ms.is_none())
            .count(),
        0,
        "no PID 4600 row may remain running after ProcessStop"
    );

    // Unresolved alert still protects `4600:0` from TTL purge; once resolved, purge removes both.
    let future_now = stop_ms + 30 * 24 * 60 * 60 * 1_000;
    let _ = store
        .purge_expired(future_now, 7)
        .expect("purge while alert unresolved");
    assert!(
        store
            .query_flight_recorder(50, Some(&placeholder_a.instance_id()))
            .expect("query protected placeholder")
            .processes
            .iter()
            .any(|p| p.process_instance_id == placeholder_a.instance_id()),
        "unresolved alert must keep placeholder row protected"
    );
    store
        .update_alert_status(
            "alert-placeholder-4600",
            AlertStatus::ApprovedOnce,
            Some(stop_ms),
        )
        .expect("resolve alert");
    let stats = store
        .purge_expired(future_now, 7)
        .expect("purge after alert resolved");
    assert!(
        stats.processes_deleted >= 1,
        "closed placeholder row must become purgeable once referencing alert is resolved"
    );
    assert!(
        store
            .query_flight_recorder(50, Some(&placeholder_a.instance_id()))
            .expect("query purged placeholder")
            .processes
            .is_empty(),
        "placeholder row should be purged after TTL once closed and unreferenced"
    );

    // Path B: canary live-process backfill upgrades `4604:0` -> `4604:<real_ts>` and closes
    // the superseded `4604:0` row atomically in SQLite.
    let placeholder_b = ProcessIdentity::new(4604, 0);
    let real_b = ProcessIdentity::new(4604, real_created_100ns);
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: placeholder_b,
            parent_pid: 4,
            exe_path: r"C:\Temp\backfill_4604.exe".to_string(),
            command_line: String::new(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    let canary_ts_4604 = {
        let table = engine.process_table.lock().unwrap_or_else(|e| e.into_inner());
        let created = table
            .lookup_by_pid(4604)
            .expect("placeholder 4604 registered")
            .created_at_ms;
        current_unix_ms().max(created)
    };
    let _ = engine.process_event_with_lane(
        &SensorEvent::CanaryFileAccess {
            pid: 4604,
            target_path: r"C:\Users\alice\.aws\credentials".to_string(),
            category: CanaryCategory::CloudCredential,
            access_mask: 1,
            is_write_or_delete: false,
            timestamp_ms: canary_ts_4604,
        },
        EventLane::HighPriority,
    );
    store.flush_batch().expect("flush backfill B");

    let snap_b = store
        .query_flight_recorder(50, None)
        .expect("query flight recorder B");
    let ph_b_row = snap_b
        .processes
        .iter()
        .find(|p| p.process_instance_id == placeholder_b.instance_id())
        .expect("placeholder B row exists");
    let real_b_row = snap_b
        .processes
        .iter()
        .find(|p| p.process_instance_id == real_b.instance_id())
        .expect("real B row exists");
    assert!(
        ph_b_row.exited_at_ms.is_some_and(|ex| ex >= ph_b_row.created_at_ms),
        "backfill-superseded placeholder 4604:0 must be closed with exited_at_ms >= created_at_ms"
    );
    assert_eq!(real_b_row.exited_at_ms, None, "backfilled real row remains active");
}

/// `PR23-U1-01`: A startup snapshot whose process creation time could not be queried
/// (`create_time_100ns == 0`) must never supersede or mark exited an already-running verified
/// process entry for the same PID in memory or SQLite, must keep subsequent network attribution
/// on the verified row, and must preserve `ProtectedOs` classification while safely enriching
/// only missing metadata on the verified row.
#[tokio::test]
async fn pr23_u1_zero_ts_snapshot_preserves_verified_running_process_and_network_attribution() {
    let store = LedrStore::open_in_memory().expect("in-memory store");
    let defense = Arc::new(RecordingDefense::new());
    let engine = start_stopped_engine(
        store.clone(),
        DaemonConfig {
            outbound_firewall_enabled: false,
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(FixedShaInspector("8".repeat(64))),
    )
    .await;

    let now_ms = current_unix_ms();
    let created_ms = now_ms - 2_000;
    let created_100ns = 116_444_736_000_000_000u64 + (created_ms as u64) * 10_000;

    // Case 1: Verified ETW ProcessStart (`4200:<real>`) -> zero-timestamp snapshot (`4200:0`)
    // -> NetworkConnect (`now_ms + 500`). Verified row must remain running, no `4200:0` row may
    // be written, network event must attribute to `4200:<real>`, and TTL purge must keep it.
    let verified_4200 = ProcessIdentity::new(4200, created_100ns);
    let zero_4200 = ProcessIdentity::new(4200, 0);
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: verified_4200,
            parent_pid: 4,
            exe_path: r"C:\Tools\verified_4200.exe".to_string(),
            command_line: "verified_4200.exe --run".to_string(),
            user_sid: Some("S-1-5-21-1000".to_string()),
        },
        EventLane::HighPriority,
    );
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: zero_4200,
            parent_pid: 4,
            exe_path: "verified_4200.exe".to_string(),
            command_line: String::new(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    let net_ts = current_unix_ms() + 500;
    let _ = engine.process_event_with_lane(
        &SensorEvent::NetworkConnect {
            pid: 4200,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            dst_port: 443,
            domain_hint: Some("example.com".to_string()),
            timestamp_ms: net_ts,
        },
        EventLane::Telemetry,
    );

    // Case 2: Verified ETW ProcessStart (`4204:<real>`) with missing `ppid` and `command_line`
    // receives zero-timestamp snapshot (`4204:0`) carrying those fields -> enriches `4204:<real>`
    // in place without creating `4204:0` in SQLite.
    let verified_4204 = ProcessIdentity::new(4204, created_100ns);
    let zero_4204 = ProcessIdentity::new(4204, 0);
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: verified_4204,
            parent_pid: 0,
            exe_path: r"C:\Tools\partial_4204.exe".to_string(),
            command_line: String::new(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: zero_4204,
            parent_pid: 888,
            exe_path: "partial_4204.exe".to_string(),
            command_line: "partial_4204.exe --enriched".to_string(),
            user_sid: Some("S-1-5-21-2000".to_string()),
        },
        EventLane::HighPriority,
    );

    // Case 3: Verified ProtectedOs process (`4208:<real>`) receiving an empty-path `4208:0`
    // snapshot must retain ProtectedOs marking and remain running.
    let verified_4208 = ProcessIdentity::new(4208, created_100ns);
    let zero_4208 = ProcessIdentity::new(4208, 0);
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: verified_4208,
            parent_pid: 4,
            exe_path: r"C:\Windows\System32\svchost.exe".to_string(),
            command_line: "svchost.exe -k netsvcs".to_string(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    assert!(engine.outbound_classifier.is_steady_pid(4208));

    // Seed through `seed_processes` as well to exercise startup snapshot reconciliation.
    let seeded = engine
        .seed_processes(vec![
            SensorEvent::ProcessStart {
                identity: zero_4200,
                parent_pid: 4,
                exe_path: String::new(),
                command_line: String::new(),
                user_sid: None,
            },
            SensorEvent::ProcessStart {
                identity: zero_4208,
                parent_pid: 4,
                exe_path: String::new(),
                command_line: String::new(),
                user_sid: None,
            },
        ])
        .expect("seed_processes with zero-ts snapshots");
    assert_eq!(seeded, 2);
    assert!(
        engine.outbound_classifier.is_steady_pid(4208),
        "zero-ts snapshot with empty path must not clear ProtectedOs steady mark"
    );

    // In-memory verification.
    {
        let table = engine.process_table.lock().unwrap_or_else(|e| e.into_inner());
        let active_4200 = table.lookup_by_pid(4200).expect("4200 must remain active");
        assert_eq!(active_4200.identity, verified_4200);
        assert_eq!(active_4200.exited_at_ms, None);
        assert!(table.get_by_instance_id(&zero_4200.instance_id()).is_none());

        let active_4204 = table.lookup_by_pid(4204).expect("4204 must remain active");
        assert_eq!(active_4204.identity, verified_4204);
        assert_eq!(active_4204.exited_at_ms, None);
        assert_eq!(active_4204.ppid, 888);
        assert_eq!(active_4204.command_line, "partial_4204.exe --enriched");
        assert!(table.get_by_instance_id(&zero_4204.instance_id()).is_none());
    }

    // SQLite verification.
    let snap = store
        .query_flight_recorder(50, None)
        .expect("query flight recorder");
    let row_4200 = snap
        .processes
        .iter()
        .find(|p| p.process_instance_id == verified_4200.instance_id())
        .expect("verified 4200 row exists");
    assert_eq!(row_4200.exited_at_ms, None, "verified 4200 must stay running in SQLite");
    assert_eq!(row_4200.exe_path, r"C:\Tools\verified_4200.exe");
    assert!(
        snap.processes
            .iter()
            .all(|p| p.process_instance_id != zero_4200.instance_id()),
        "synthetic 4200:0 row must not be inserted into SQLite"
    );
    let net_row = snap
        .network_events
        .iter()
        .find(|n| n.dst_port == 443)
        .expect("network event recorded");
    assert_eq!(
        net_row.process_instance_id,
        verified_4200.instance_id(),
        "subsequent network event must attribute to verified 4200 row"
    );

    let row_4204 = snap
        .processes
        .iter()
        .find(|p| p.process_instance_id == verified_4204.instance_id())
        .expect("verified 4204 row exists");
    assert_eq!(row_4204.exited_at_ms, None, "verified 4204 must stay running");
    assert_eq!(
        row_4204.exe_path,
        r"C:\Tools\partial_4204.exe",
        "snapshot basename must not overwrite verified full exe_path in SQLite"
    );
    assert_eq!(row_4204.ppid, 888, "missing ppid must be enriched on verified 4204");
    assert_eq!(
        row_4204.command_line.as_deref(),
        Some("partial_4204.exe --enriched")
    );
    assert!(
        snap.processes
            .iter()
            .all(|p| p.process_instance_id != zero_4204.instance_id()),
        "synthetic 4204:0 row must not be inserted into SQLite on enrichment"
    );

    // Running verified row must survive TTL purge far in the future.
    let future_now = net_ts + 30 * 24 * 60 * 60 * 1_000;
    let _ = store.purge_expired(future_now, 7).expect("purge expired");
    assert!(
        store
            .query_flight_recorder(50, Some(&verified_4200.instance_id()))
            .expect("query after purge")
            .processes
            .iter()
            .any(|p| p.process_instance_id == verified_4200.instance_id()),
        "running verified 4200 row must not be TTL-purged"
    );
}

/// `PR23-U3-01`: Shutdown suspension clearing must separate actually resumed identities
/// (`shutdown_resumed_identities` / `shutdown_resumed_at_ms`) from already-exited or PID-reused
/// identities (`shutdown_gone_identities` / `shutdown_cleared_at_ms`).
#[tokio::test]
async fn pr23_u3_shutdown_clear_distinguishes_resumed_vs_gone_in_audit_context() {
    struct SelectiveGoneResumeDefense {
        gone_targets: std::collections::HashSet<ProcessIdentity>,
        resumed: Mutex<Vec<ProcessIdentity>>,
    }

    impl ActiveDefenseController for SelectiveGoneResumeDefense {
        fn suspend_process(&self, _target: &ProcessIdentity, _include_children: bool) -> Result<(), String> {
            Ok(())
        }

        fn resume_process(&self, target: &ProcessIdentity) -> Result<(), String> {
            if self.gone_targets.contains(target) {
                return Err(format!(
                    "CreationTime mismatch for PID {}: expected {}, got 999",
                    target.pid, target.create_time_100ns
                ));
            }
            self.resumed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(*target);
            Ok(())
        }

        fn terminate_process(&self, _target: &ProcessIdentity, _include_children: bool) -> Result<(), String> {
            Ok(())
        }

        fn add_wfp_app_rule(&self, _exe_path: &Path, _remote_ip: Option<IpAddr>, _allow: bool) -> Result<u64, String> {
            Ok(1)
        }

        fn remove_wfp_rule(&self, _filter_id: u64) -> Result<(), String> {
            Ok(())
        }
    }

    let store = LedrStore::open_in_memory().expect("in-memory store");
    let gone_only_parent = ProcessIdentity::new(5100, 133_800_000_000_005_100);
    let mixed_parent = ProcessIdentity::new(5200, 133_800_000_000_005_200);
    let mixed_gone_child = ProcessIdentity::new(5204, 133_800_000_000_005_204);
    let resumed_only_parent = ProcessIdentity::new(5300, 133_800_000_000_005_300);

    let defense = Arc::new(SelectiveGoneResumeDefense {
        gone_targets: [gone_only_parent, mixed_gone_child].into_iter().collect(),
        resumed: Mutex::new(Vec::new()),
    });

    let engine = DaemonEngine::start_with_dependencies(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            outbound_firewall_enabled: false,
            resume_suspended_on_shutdown: true,
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(StubNotifier),
        Arc::new(FixedShaInspector("a".repeat(64))),
    );

    let now_ms = current_unix_ms();
    // Alert A: gone/PID-reused parent only.
    store
        .record_alert(&AlertRecord {
            alert_id: "alert-u3-gone-only".to_string(),
            timestamp_ms: now_ms,
            severity: AlertSeverity::High,
            source_layer: "LAYER_1_CANARY".to_string(),
            rule_id: "LEDR-CANARY-SSH_KEY".to_string(),
            title: "Gone parent expired alert".to_string(),
            process_instance_id: Some(gone_only_parent.instance_id()),
            process_suspended: true,
            status: AlertStatus::ExpiredSuspended,
            context_json: r#"{"suspended_children":[]}"#.to_string(),
            resolved_at_ms: None,
        })
        .expect("seed gone-only alert");

    // Alert B: resumed parent + gone child.
    store
        .record_alert(&AlertRecord {
            alert_id: "alert-u3-mixed".to_string(),
            timestamp_ms: now_ms,
            severity: AlertSeverity::Critical,
            source_layer: "LAYER_1_CANARY".to_string(),
            rule_id: "LEDR-CANARY-HONEYPOT".to_string(),
            title: "Mixed parent/child expired alert".to_string(),
            process_instance_id: Some(mixed_parent.instance_id()),
            process_suspended: true,
            status: AlertStatus::ExpiredSuspended,
            context_json: serde_json::json!({
                "suspended_children": [mixed_gone_child.instance_id()]
            })
            .to_string(),
            resolved_at_ms: None,
        })
        .expect("seed mixed alert");

    // Alert C: resumed parent only.
    store
        .record_alert(&AlertRecord {
            alert_id: "alert-u3-resumed-only".to_string(),
            timestamp_ms: now_ms,
            severity: AlertSeverity::High,
            source_layer: "LAYER_1_CANARY".to_string(),
            rule_id: "LEDR-CANARY-COOKIE_DB".to_string(),
            title: "Resumed parent expired alert".to_string(),
            process_instance_id: Some(resumed_only_parent.instance_id()),
            process_suspended: true,
            status: AlertStatus::ExpiredSuspended,
            context_json: r#"{"suspended_children":[]}"#.to_string(),
            resolved_at_ms: None,
        })
        .expect("seed resumed-only alert");

    engine.shutdown_and_flush().await.expect("shutdown");

    // Alert A: only shutdown_gone_identities + shutdown_cleared_at_ms, NO shutdown_resumed_*.
    let a = store.get_alert("alert-u3-gone-only").unwrap().unwrap();
    assert!(!a.process_suspended);
    let ctx_a: serde_json::Value = serde_json::from_str(&a.context_json).unwrap();
    assert_eq!(
        ctx_a["shutdown_gone_identities"],
        serde_json::json!([gone_only_parent.instance_id()])
    );
    assert!(ctx_a["shutdown_cleared_at_ms"].as_i64().is_some());
    assert!(
        ctx_a.get("shutdown_resumed_at_ms").is_none(),
        "gone-only clear must not set shutdown_resumed_at_ms: {ctx_a}"
    );
    assert!(
        ctx_a.get("shutdown_resumed_identities").is_none(),
        "gone-only clear must not set shutdown_resumed_identities: {ctx_a}"
    );

    // Alert B: both resumed and gone audit trails recorded separately.
    let b = store.get_alert("alert-u3-mixed").unwrap().unwrap();
    assert!(!b.process_suspended);
    let ctx_b: serde_json::Value = serde_json::from_str(&b.context_json).unwrap();
    assert_eq!(ctx_b["suspended_children"], serde_json::json!([]));
    assert_eq!(
        ctx_b["shutdown_resumed_identities"],
        serde_json::json!([mixed_parent.instance_id()])
    );
    assert!(ctx_b["shutdown_resumed_at_ms"].as_i64().is_some());
    assert_eq!(
        ctx_b["shutdown_gone_identities"],
        serde_json::json!([mixed_gone_child.instance_id()])
    );
    assert!(ctx_b["shutdown_cleared_at_ms"].as_i64().is_some());

    // Alert C: only shutdown_resumed_identities + shutdown_resumed_at_ms, NO shutdown_gone/cleared.
    let c = store.get_alert("alert-u3-resumed-only").unwrap().unwrap();
    assert!(!c.process_suspended);
    let ctx_c: serde_json::Value = serde_json::from_str(&c.context_json).unwrap();
    assert_eq!(
        ctx_c["shutdown_resumed_identities"],
        serde_json::json!([resumed_only_parent.instance_id()])
    );
    assert!(ctx_c["shutdown_resumed_at_ms"].as_i64().is_some());
    assert!(ctx_c.get("shutdown_cleared_at_ms").is_none());
    assert!(ctx_c.get("shutdown_gone_identities").is_none());
}

/// `PR23-R26-T1-02`: Integration verification that a zero-timestamp snapshot for an existing
/// verified child cannot attach the child to a newer unrelated process that reused its parent
/// PID in SQLite or cause canary descendant suspension to freeze the unrelated child.
#[tokio::test]
async fn pr23_r26_t1_reused_parent_pid_not_linked_or_frozen_on_canary() {
    let store = LedrStore::open_in_memory().expect("in-memory store");
    let defense = Arc::new(RecordingDefense::new());
    let engine = start_stopped_engine(
        store.clone(),
        DaemonConfig {
            outbound_firewall_enabled: false,
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(FixedShaInspector("7".repeat(64))),
    )
    .await;

    let now_ms = current_unix_ms();
    let child_b_ms = now_ms - 5_000;
    let proc_c_ms = now_ms - 1_000;
    let child_b_100ns = 116_444_736_000_000_000u64 + (child_b_ms as u64) * 10_000;
    let proc_c_100ns = 116_444_736_000_000_000u64 + (proc_c_ms as u64) * 10_000;

    let child_b = ProcessIdentity::new(4804, child_b_100ns);
    let proc_c = ProcessIdentity::new(4800, proc_c_100ns);

    // Child B starts earlier with parent PID 4800 (original parent A is absent from table).
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: child_b,
            parent_pid: 4800,
            exe_path: r"C:\Tools\child_b.exe".to_string(),
            command_line: "child_b.exe --worker".to_string(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );

    // Later, unrelated process C reuses PID 4800.
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: proc_c,
            parent_pid: 4,
            exe_path: r"C:\Tools\unrelated_c.exe".to_string(),
            command_line: "unrelated_c.exe".to_string(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );

    // Zero-timestamp snapshot for child B arrives after C took PID 4800.
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: ProcessIdentity::new(4804, 0),
            parent_pid: 4800,
            exe_path: r"C:\Tools\child_b.exe".to_string(),
            command_line: "child_b.exe --worker".to_string(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );

    // Unrelated C writes to a Honeypot decoy: only C may be suspended, never B.
    let _ = engine.process_event_with_lane(
        &SensorEvent::CanaryFileAccess {
            pid: 4800,
            target_path: r"C:\Users\alice\Documents\.ledr-canary-test.txt".to_string(),
            category: CanaryCategory::Honeypot,
            access_mask: 0x0012_0089,
            is_write_or_delete: true,
            timestamp_ms: now_ms,
        },
        EventLane::HighPriority,
    );

    let snap = store
        .query_flight_recorder(50, None)
        .expect("query flight recorder");
    let b_row = snap
        .processes
        .iter()
        .find(|p| p.process_instance_id == child_b.instance_id())
        .expect("child B row exists in SQLite");
    assert_eq!(
        b_row.parent_instance_id, None,
        "child B must not be linked to newer unrelated C in SQLite"
    );

    let suspended = defense.suspended();
    assert_eq!(
        suspended,
        vec![proc_c],
        "only C may be suspended; child B must not be frozen"
    );

    let alerts = store.list_alerts(None, 20).expect("list alerts");
    let honeypot_alert = alerts
        .iter()
        .find(|a| a.process_instance_id.as_deref() == Some(proc_c.instance_id().as_str()))
        .expect("honeypot alert for C exists");
    let ctx: serde_json::Value =
        serde_json::from_str(&honeypot_alert.context_json).expect("valid alert context");
    let suspended_children = ctx["suspended_children"]
        .as_array()
        .expect("suspended_children array");
    assert!(
        !suspended_children
            .iter()
            .any(|v| v.as_str() == Some(child_b.instance_id().as_str())),
        "unrelated child B must not be recorded in suspended_children: {ctx}"
    );
}

/// `PR23-R26-T2-01`: Parent-only enrichment (`create_time_100ns == 0` snapshot or same
/// `instance_id` re-observation with empty `exe_path`/`command_line`) must re-evaluate Sigma
/// using the consolidated launch metadata (`LEDR-LOTL-001`) and persist the merged event in alert
/// context.
#[tokio::test]
async fn pr23_r26_t2_parent_only_enrichment_reevaluates_sigma_with_merged_launch_info() {
    let store = LedrStore::open_in_memory().expect("in-memory store");
    let defense = Arc::new(RecordingDefense::new());
    let rules_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/lotl_core.json");
    let sigma = SigmaEngine::from_json_file(&rules_path).expect("load lotl_core.json");

    let engine = DaemonEngine::start_with_dependencies(
        store.clone(),
        sigma,
        EarlyPruner::default(),
        DaemonConfig {
            outbound_firewall_enabled: false,
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(StubNotifier),
        Arc::new(FixedShaInspector("6".repeat(64))),
    );
    if let Some(h) = engine.worker_handle.lock().await.take() {
        h.abort();
        let _ = h.await;
    }

    let now_ms = current_unix_ms();
    let parent_ms = now_ms - 10_000;
    let child_a_ms = now_ms - 5_000;
    let child_b_ms = now_ms - 4_000;
    let parent_100ns = 116_444_736_000_000_000u64 + (parent_ms as u64) * 10_000;
    let child_a_100ns = 116_444_736_000_000_000u64 + (child_a_ms as u64) * 10_000;
    let child_b_100ns = 116_444_736_000_000_000u64 + (child_b_ms as u64) * 10_000;

    let cmd_parent = ProcessIdentity::new(4900, parent_100ns);
    let ps_a = ProcessIdentity::new(4904, child_a_100ns);
    let ps_b = ProcessIdentity::new(4908, child_b_100ns);
    let ps_exe = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    let ps_cmd = "powershell.exe -enc SQBFAFgA";

    // Subcase (a): Verified PowerShell arrives without parent_pid -> LEDR-LOTL-001 cannot match yet.
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: ps_a,
            parent_pid: 0,
            exe_path: ps_exe.to_string(),
            command_line: ps_cmd.to_string(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    assert!(
        store.list_alerts(None, 20).expect("list alerts").is_empty(),
        "LEDR-LOTL-001 must not fire before cmd.exe parent is known"
    );

    // Subcase (b) initial event: second PowerShell arrives before parent cmd.exe as well.
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: ps_b,
            parent_pid: 0,
            exe_path: ps_exe.to_string(),
            command_line: ps_cmd.to_string(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    assert!(
        store.list_alerts(None, 20).expect("list alerts").is_empty(),
        "LEDR-LOTL-001 must not fire for ps_b before parent is known"
    );

    // Parent cmd.exe arrives.
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: cmd_parent,
            parent_pid: 4,
            exe_path: r"C:\Windows\System32\cmd.exe".to_string(),
            command_line: "cmd.exe /c powershell.exe".to_string(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );

    // Subcase (a) enrichment: zero-timestamp snapshot supplies ONLY parent_pid (empty exe/cmd).
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: ProcessIdentity::new(4904, 0),
            parent_pid: 4900,
            exe_path: String::new(),
            command_line: String::new(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );

    // Subcase (b) enrichment: same instance_id supplies ONLY parent_pid (empty exe/cmd).
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: ps_b,
            parent_pid: 4900,
            exe_path: String::new(),
            command_line: String::new(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );

    let alerts = store.list_alerts(None, 20).expect("list alerts");
    for (label, ident) in [("zero-ts snapshot", ps_a), ("same instance_id", ps_b)] {
        let alert = alerts
            .iter()
            .find(|a| {
                a.rule_id == "LEDR-LOTL-001"
                    && a.process_instance_id.as_deref() == Some(ident.instance_id().as_str())
            })
            .unwrap_or_else(|| panic!("expected LEDR-LOTL-001 alert for {label} ({ident:?}); got {alerts:?}"));
        let ctx: serde_json::Value =
            serde_json::from_str(&alert.context_json).expect("valid alert context");
        assert_eq!(
            ctx["parent_exe_path"].as_str(),
            Some(r"C:\Windows\System32\cmd.exe")
        );
        assert_eq!(
            ctx["event"]["ProcessStart"]["exe_path"].as_str(),
            Some(ps_exe),
            "alert context event must carry merged verified exe_path for {label}"
        );
        assert_eq!(
            ctx["event"]["ProcessStart"]["command_line"].as_str(),
            Some(ps_cmd),
            "alert context event must carry merged verified command_line for {label}"
        );
        assert_eq!(
            ctx["event"]["ProcessStart"]["parent_pid"].as_u64(),
            Some(4900)
        );
    }
}

/// `PR23-R30-T1-02`: When an ETW `ProcessStart` arrives with `parent_pid = 0` (omitted by ETW),
/// a subsequent same-instance Toolhelp32 snapshot carrying the real `parent_pid` must correct
/// both `ppid` and `parent_instance_id` in memory and SQLite without losing existing metadata or
/// allowing a later conflicting `parent_pid` to overwrite the confirmed parent.
#[tokio::test]
async fn pr23_r30_t1_same_instance_snapshot_corrects_missing_etw_ppid_in_memory_and_sqlite() {
    let store = LedrStore::open_in_memory().expect("in-memory store");
    let defense = Arc::new(RecordingDefense::new());
    let engine = start_stopped_engine(
        store.clone(),
        DaemonConfig {
            outbound_firewall_enabled: false,
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(FixedShaInspector("5".repeat(64))),
    )
    .await;

    let now_ms = current_unix_ms();
    let parent_ms = now_ms - 10_000;
    let child_ms = now_ms - 5_000;
    let parent_100ns = 116_444_736_000_000_000u64 + (parent_ms as u64) * 10_000;
    let child_100ns = 116_444_736_000_000_000u64 + (child_ms as u64) * 10_000;

    let parent_1200 = ProcessIdentity::new(4920, parent_100ns);
    let child = ProcessIdentity::new(4924, child_100ns);
    let child_exe = r"C:\Tools\worker.exe";
    let child_cmd = "worker.exe --run";

    // 1. Initial ETW ProcessStart arrives with unknown parent_pid = 0.
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: child,
            parent_pid: 0,
            exe_path: child_exe.to_string(),
            command_line: child_cmd.to_string(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );

    store.flush_batch().expect("flush initial child");
    let initial_snap = store
        .query_flight_recorder(50, Some(&child.instance_id()))
        .expect("query initial child");
    let initial_row = initial_snap
        .processes
        .iter()
        .find(|p| p.process_instance_id == child.instance_id())
        .expect("initial child row exists");
    assert_eq!(initial_row.ppid, 0);
    assert_eq!(initial_row.parent_instance_id, None);

    // 2. Real parent arrives, followed by same-instance Toolhelp32 snapshot carrying ppid = 4920
    //    and empty command_line.
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: parent_1200,
            parent_pid: 4,
            exe_path: r"C:\Windows\System32\cmd.exe".to_string(),
            command_line: "cmd.exe".to_string(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: child,
            parent_pid: 4920,
            exe_path: child_exe.to_string(),
            command_line: String::new(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );

    {
        let table = engine.process_table.lock().unwrap_or_else(|e| e.into_inner());
        let entry = table
            .get_by_instance_id(&child.instance_id())
            .expect("child entry in memory");
        assert_eq!(entry.ppid, 4920);
        assert_eq!(
            entry.parent_instance_id.as_deref(),
            Some(parent_1200.instance_id().as_str())
        );
    }

    store.flush_batch().expect("flush corrected child");
    let corrected_snap = store
        .query_flight_recorder(50, Some(&child.instance_id()))
        .expect("query corrected child");
    let corrected_row = corrected_snap
        .processes
        .iter()
        .find(|p| p.process_instance_id == child.instance_id())
        .expect("corrected child row exists");
    assert_eq!(corrected_row.ppid, 4920);
    assert_eq!(
        corrected_row.parent_instance_id.as_deref(),
        Some(parent_1200.instance_id().as_str())
    );
    assert_eq!(corrected_row.command_line.as_deref(), Some(child_cmd));

    // 3. Subsequent conflicting parent_pid (9999) must NOT overwrite confirmed ppid/parent_instance_id.
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: child,
            parent_pid: 9999,
            exe_path: child_exe.to_string(),
            command_line: String::new(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    store.flush_batch().expect("flush after conflict");
    let after_conflict_snap = store
        .query_flight_recorder(50, Some(&child.instance_id()))
        .expect("query after conflicting ppid");
    let after_conflict_row = after_conflict_snap
        .processes
        .iter()
        .find(|p| p.process_instance_id == child.instance_id())
        .expect("child row after conflict exists");
    assert_eq!(after_conflict_row.ppid, 4920);
    assert_eq!(
        after_conflict_row.parent_instance_id.as_deref(),
        Some(parent_1200.instance_id().as_str())
    );
}

/// `DAEMON-PERF-FASTPATH-01`: `verified_app_wide_allows` skips redundant `BinaryInspector::inspect`
/// (disk SHA-256 + Authenticode) on repeated connects of a verified `create_time_100ns != 0`
/// browser/app-wide `NetworkAllow` process, while strictly respecting:
/// - bounded FIFO capacity (`4,096`),
/// - direct `store.upsert_rule` rule fingerprint changes, `NetworkBlock` addition, and
///   destination-scoped (`allowed_target != None`) rule addition,
/// - `create_time_100ns == 0` exclusion,
/// - invalidation on `ProcessStop`, `ActiveProcessTable` eviction, and
///   `invalidate_non_protected_steady_pids()`,
/// - non-Audit app-wide WFP Permit requirement vs Audit mode allowance.
#[tokio::test]
async fn daemon_perf_fastpath_01_verified_app_wide_allow_fast_path_and_invalidation() {
    use crate::engine::outbound::{VerifiedAppWideAllowCache, VerifiedAppWideAllowEntry};
    use ledr_proto::AuthenticodeInfo;
    use std::sync::atomic::AtomicUsize;

    struct SignedCountingInspector {
        calls: AtomicUsize,
        sha256: String,
        signer: String,
        thumbprint: String,
    }

    impl SignedCountingInspector {
        fn new(sha256: &str, signer: &str, thumbprint: &str) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                sha256: sha256.to_string(),
                signer: signer.to_string(),
                thumbprint: thumbprint.to_string(),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::Acquire)
        }
    }

    impl crate::engine::BinaryInspector for SignedCountingInspector {
        fn inspect(&self, exe_path: &str) -> ledr_rules::BinaryIdentity {
            self.calls.fetch_add(1, Ordering::AcqRel);
            ledr_rules::BinaryIdentity {
                exe_path: exe_path.to_string(),
                sha256: Some(self.sha256.clone()),
                authenticode: Some(AuthenticodeInfo {
                    signer_subject: self.signer.clone(),
                    root_thumbprint: self.thumbprint.clone(),
                }),
            }
        }
    }

    struct FailingPermitDefense;

    impl ActiveDefenseController for FailingPermitDefense {
        fn suspend_process(&self, _: &ProcessIdentity, _: bool) -> Result<(), String> {
            Ok(())
        }
        fn resume_process(&self, _: &ProcessIdentity) -> Result<(), String> {
            Ok(())
        }
        fn terminate_process(&self, _: &ProcessIdentity, _: bool) -> Result<(), String> {
            Ok(())
        }
        fn add_wfp_app_rule(&self, _: &Path, _: Option<IpAddr>, allow: bool) -> Result<u64, String> {
            if allow {
                Err("injected WFP permit registration failure".to_string())
            } else {
                Ok(1)
            }
        }
        fn remove_wfp_rule(&self, _: u64) -> Result<(), String> {
            Ok(())
        }
    }

    let browser_rule = AllowlistRuleRecord {
        rule_id: "ALLOW-NET-BROWSER-CHROME".to_string(),
        scope: RuleScope::NetworkAllow,
        exe_path_pattern: r"C:\Program Files*\Google\Chrome\Application\chrome.exe".to_string(),
        sha256: None,
        signer_subject: Some("CN=Google LLC".to_string()),
        root_thumbprint: Some("DDFB16CD4931C973A2037D3FC83A4D7D775D05E4".to_string()),
        allowed_target: None,
        created_at_ms: 1_760_000_000_000,
        created_by: "default_allowlist".to_string(),
    };

    // Part A: Bounded FIFO eviction, generation-tracked compaction, and re-insert order check
    // on `VerifiedAppWideAllowCache`.
    {
        let mut cache = VerifiedAppWideAllowCache::new(3);
        let mk_entry = || VerifiedAppWideAllowEntry {
            exe_key: Arc::from(r"c:\program files\google\chrome\application\chrome.exe"),
            authorizing_rule: browser_rule.clone(),
        };
        for i in 1..=4 {
            cache.insert(format!("{i}:100"), mk_entry());
        }
        assert_eq!(cache.len(), 3);
        assert!(cache.get("1:100").is_none(), "oldest entry must be FIFO-evicted");
        assert!(cache.get("2:100").is_some());
        assert!(cache.get("4:100").is_some());
        // Updating existing entry must not evict live neighbors.
        cache.insert("2:100".to_string(), mk_entry());
        assert_eq!(cache.len(), 3);
        assert!(cache.get("3:100").is_some());
        cache.clear();
        assert_eq!(cache.len(), 0);

        // Repeated remove + re-insert of the same key must keep `order` strictly bounded (no
        // duplicate accumulation defeating compaction) and must not prematurely evict the freshly
        // re-inserted entry ahead of older keys.
        for _ in 0..1_000 {
            cache.insert("same:1".to_string(), mk_entry());
            assert!(cache.remove("same:1"));
        }
        assert!(
            cache.order_len() <= 6,
            "stale order entries must be compacted strictly within 2 * capacity (got {})",
            cache.order_len()
        );
        cache.clear();
        cache.insert("a:1".to_string(), mk_entry());
        assert!(cache.remove("a:1"));
        cache.insert("b:1".to_string(), mk_entry());
        cache.insert("c:1".to_string(), mk_entry());
        cache.insert("a:1".to_string(), mk_entry()); // newest entry despite earlier removed `a:1`
        cache.insert("d:1".to_string(), mk_entry()); // must evict `b:1`, NOT freshly re-inserted `a:1`
        assert!(cache.get("b:1").is_none(), "oldest live entry `b:1` must be evicted");
        assert!(cache.get("a:1").is_some(), "freshly re-inserted `a:1` must survive eviction");
        assert!(cache.get("c:1").is_some());
        assert!(cache.get("d:1").is_some());
        cache.clear();
        assert_eq!(cache.len(), 0);
    }

    // Part B: Post-startup wildcard browser allowlist + fast path + direct SQLite rule mutations +
    // ProcessStop + ActiveProcessTable eviction + invalidate_non_protected_steady_pids().
    let chrome_exe = r"C:\Program Files\Google\Chrome\Application\chrome.exe";
    let store = LedrStore::open_in_memory().expect("open store");
    store
        .upsert_rule(&browser_rule)
        .expect("seed browser allow rule");

    let defense = Arc::new(RecordingDefense::new());
    let inspector = Arc::new(SignedCountingInspector::new(
        &"a".repeat(64),
        "CN=Google LLC",
        "DDFB16CD4931C973A2037D3FC83A4D7D775D05E4",
    ));
    let engine = start_stopped_engine(
        store.clone(),
        DaemonConfig {
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::PreemptiveOnly,
            active_process_capacity: 2,
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::clone(&inspector) as Arc<dyn crate::engine::BinaryInspector>,
    )
    .await;

    let chrome_1 = ProcessIdentity::new(7101, 700_001);
    send_process_start(&engine, chrome_1, chrome_exe);
    let calls_after_start = inspector.calls();
    let now_ms = current_unix_ms();

    // Connect #1 verifies the binary, materializes the app-wide WFP Permit, promotes steady PID,
    // and populates `verified_app_wide_allows`.
    let _ = engine.process_event_with_lane(
        &SensorEvent::NetworkConnect {
            pid: chrome_1.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(142, 250, 190, 78)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms,
        },
        EventLane::HighPriority,
    );
    let calls_after_first_connect = inspector.calls();
    assert_eq!(
        calls_after_first_connect,
        calls_after_start + 1,
        "first outbound connect must run BinaryInspector once"
    );
    assert!(
        engine.has_active_wfp_filter(chrome_exe, None, true),
        "post-startup wildcard browser allow must materialize app-wide WFP Permit"
    );
    assert_eq!(engine.verified_app_wide_allows_len(), 1);

    // Connects #2..=#10 across distinct destinations must skip BinaryInspector completely.
    for i in 1..=9u8 {
        let _ = engine.process_event_with_lane(
            &SensorEvent::NetworkConnect {
                pid: chrome_1.pid,
                protocol: 6,
                dst_ip: IpAddr::V4(Ipv4Addr::new(142, 250, 190, 80 + i)),
                dst_port: 443,
                domain_hint: None,
                timestamp_ms: now_ms + i64::from(i),
            },
            EventLane::Telemetry,
        );
    }
    assert_eq!(
        inspector.calls(),
        calls_after_first_connect,
        "subsequent connects for verified app-wide allowed browser must skip BinaryInspector"
    );

    // Direct SQLite mutation #1 (bypassing DaemonEngine): adding a destination-scoped rule must
    // immediately disable the fast path and re-invoke BinaryInspector.
    let scoped_rule = AllowlistRuleRecord {
        rule_id: "ALLOW-CHROME-SCOPED".to_string(),
        scope: RuleScope::NetworkAllow,
        exe_path_pattern: chrome_exe.to_string(),
        sha256: None,
        signer_subject: Some("CN=Google LLC".to_string()),
        root_thumbprint: Some("DDFB16CD4931C973A2037D3FC83A4D7D775D05E4".to_string()),
        allowed_target: Some("api.example.com".to_string()),
        created_at_ms: now_ms + 20,
        created_by: "test".to_string(),
    };
    store.upsert_rule(&scoped_rule).expect("insert scoped rule directly");
    let _ = engine.process_event_with_lane(
        &SensorEvent::NetworkConnect {
            pid: chrome_1.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(142, 250, 190, 99)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms + 21,
        },
        EventLane::HighPriority,
    );
    assert_eq!(
        inspector.calls(),
        calls_after_first_connect + 1,
        "direct store.upsert_rule of destination-scoped rule must bypass fast path"
    );
    assert_eq!(engine.verified_app_wide_allows_len(), 0);
    store
        .delete_rule(&scoped_rule.rule_id)
        .expect("remove scoped rule");

    // Re-populate fast path once, then test direct SQLite `NetworkBlock` insertion.
    let _ = engine.process_event_with_lane(
        &SensorEvent::NetworkConnect {
            pid: chrome_1.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(142, 250, 190, 100)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms + 22,
        },
        EventLane::HighPriority,
    );
    assert_eq!(engine.verified_app_wide_allows_len(), 1);
    let calls_before_block = inspector.calls();

    let block_rule = AllowlistRuleRecord {
        rule_id: "BLOCK-CHROME-DIRECT".to_string(),
        scope: RuleScope::NetworkBlock,
        exe_path_pattern: chrome_exe.to_string(),
        sha256: None,
        signer_subject: None,
        root_thumbprint: None,
        allowed_target: Some("203.0.113.55".to_string()),
        created_at_ms: now_ms + 23,
        created_by: "test".to_string(),
    };
    store
        .upsert_rule(&block_rule)
        .expect("insert block rule directly");
    let _ = engine.process_event_with_lane(
        &SensorEvent::NetworkConnect {
            pid: chrome_1.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 55)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms + 24,
        },
        EventLane::HighPriority,
    );
    assert_eq!(
        inspector.calls(),
        calls_before_block + 1,
        "direct store.upsert_rule of NetworkBlock must invalidate fast path and evaluate block"
    );
    assert!(
        engine.has_active_wfp_filter(chrome_exe, Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 55))), false),
        "NetworkBlock added directly in store must take effect immediately"
    );
    store
        .delete_rule(&block_rule.rule_id)
        .expect("remove block rule");
    let _ = engine.deploy_persisted_network_rules();

    // Direct SQLite mutation #3: changing authorizing rule content (fingerprint mismatch) must
    // bypass the fast path and re-run BinaryInspector.
    let _ = engine.process_event_with_lane(
        &SensorEvent::NetworkConnect {
            pid: chrome_1.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(142, 250, 190, 101)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms + 25,
        },
        EventLane::HighPriority,
    );
    assert_eq!(engine.verified_app_wide_allows_len(), 1);
    let calls_before_rule_edit = inspector.calls();
    let mut edited_rule = browser_rule.clone();
    edited_rule.signer_subject = Some("CN=Different Signer".to_string());
    store
        .upsert_rule(&edited_rule)
        .expect("edit authorizing rule directly");
    let _ = engine.process_event_with_lane(
        &SensorEvent::NetworkConnect {
            pid: chrome_1.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(142, 250, 190, 102)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms + 26,
        },
        EventLane::HighPriority,
    );
    assert_eq!(
        inspector.calls(),
        calls_before_rule_edit + 1,
        "mutating authorizing rule content directly must invalidate fast path"
    );
    // Restore original rule and re-deploy.
    store
        .upsert_rule(&browser_rule)
        .expect("restore original browser rule");
    let _ = engine.deploy_persisted_network_rules();

    // Re-populate fast path, then verify `invalidate_non_protected_steady_pids()` clears it.
    let _ = engine.process_event_with_lane(
        &SensorEvent::NetworkConnect {
            pid: chrome_1.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(142, 250, 190, 103)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms + 27,
        },
        EventLane::HighPriority,
    );
    assert_eq!(engine.verified_app_wide_allows_len(), 1);
    engine.invalidate_non_protected_steady_pids();
    assert_eq!(engine.verified_app_wide_allows_len(), 0);

    // Re-populate fast path, then verify `ProcessStop` invalidates `chrome_1`.
    let _ = engine.process_event_with_lane(
        &SensorEvent::NetworkConnect {
            pid: chrome_1.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(142, 250, 190, 104)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms + 28,
        },
        EventLane::HighPriority,
    );
    assert_eq!(engine.verified_app_wide_allows_len(), 1);
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStop {
            pid: chrome_1.pid,
            exit_code: 0,
            exit_time_100ns: 700_099,
        },
        EventLane::HighPriority,
    );
    assert_eq!(
        engine.verified_app_wide_allows_len(),
        0,
        "ProcessStop must evict verified_app_wide_allows entry"
    );

    // ActiveProcessTable capacity eviction (`active_process_capacity = 2`) must also evict.
    let chrome_2 = ProcessIdentity::new(7102, 700_002);
    send_process_start(&engine, chrome_2, chrome_exe);
    let chrome_2_ts = current_unix_ms();
    let _ = engine.process_event_with_lane(
        &SensorEvent::NetworkConnect {
            pid: chrome_2.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(142, 250, 190, 105)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: chrome_2_ts,
        },
        EventLane::HighPriority,
    );
    assert_eq!(engine.verified_app_wide_allows_len(), 1);
    // Start 2 more processes to push `chrome_2` out of the 2-slot `ActiveProcessTable`.
    send_process_start(
        &engine,
        ProcessIdentity::new(7103, 700_003),
        r"C:\Apps\other1.exe",
    );
    send_process_start(
        &engine,
        ProcessIdentity::new(7104, 700_004),
        r"C:\Apps\other2.exe",
    );
    assert_eq!(
        engine.verified_app_wide_allows_len(),
        0,
        "ActiveProcessTable eviction must remove evicted process_instance_id from verified_app_wide_allows"
    );

    // Part C: `create_time_100ns == 0` must NEVER be cached in `verified_app_wide_allows`.
    let unverified_pid0 = ProcessIdentity::new(7105, 0);
    send_process_start(&engine, unverified_pid0, chrome_exe);
    let pid0_ts = current_unix_ms();
    let calls_before_pid0 = inspector.calls();
    for i in 0..3i64 {
        let _ = engine.process_event_with_lane(
            &SensorEvent::NetworkConnect {
                pid: unverified_pid0.pid,
                protocol: 6,
                dst_ip: IpAddr::V4(Ipv4Addr::new(142, 250, 190, 110)),
                dst_port: 443 + i as u16,
                domain_hint: None,
                timestamp_ms: pid0_ts + i,
            },
            EventLane::HighPriority,
        );
    }
    assert_eq!(
        inspector.calls(),
        calls_before_pid0 + 3,
        "create_time_100ns == 0 processes must never use verified_app_wide_allows"
    );
    assert_eq!(engine.verified_app_wide_allows_len(), 0);

    // Part D: Non-Audit mode without active app-wide WFP Permit (permit install fails) must NOT
    // engage the fast path, whereas Audit mode engages it without requiring a WFP Permit.
    let store_fail = LedrStore::open_in_memory().expect("open store fail");
    store_fail
        .upsert_rule(&browser_rule)
        .expect("seed browser allow");
    let insp_fail = Arc::new(SignedCountingInspector::new(
        &"b".repeat(64),
        "CN=Google LLC",
        "DDFB16CD4931C973A2037D3FC83A4D7D775D05E4",
    ));
    let engine_fail = start_stopped_engine(
        store_fail,
        DaemonConfig {
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::Enforce,
            ..DaemonConfig::default()
        },
        Arc::new(FailingPermitDefense) as Arc<dyn ActiveDefenseController>,
        Arc::clone(&insp_fail) as Arc<dyn crate::engine::BinaryInspector>,
    )
    .await;
    let p_fail = ProcessIdentity::new(7201, 700_201);
    send_process_start(&engine_fail, p_fail, chrome_exe);
    let fail_ts = current_unix_ms();
    let calls_fail_start = insp_fail.calls();
    for i in 0..3i64 {
        let _ = engine_fail.process_event_with_lane(
            &SensorEvent::NetworkConnect {
                pid: p_fail.pid,
                protocol: 6,
                dst_ip: IpAddr::V4(Ipv4Addr::new(142, 250, 190, 120)),
                dst_port: 443 + i as u16,
                domain_hint: None,
                timestamp_ms: fail_ts + i,
            },
            EventLane::HighPriority,
        );
    }
    assert_eq!(
        insp_fail.calls(),
        calls_fail_start + 3,
        "non-Audit mode without active app-wide WFP Permit must not cache fast path"
    );
    assert_eq!(engine_fail.verified_app_wide_allows_len(), 0);

    let store_audit = LedrStore::open_in_memory().expect("open store audit");
    store_audit
        .upsert_rule(&browser_rule)
        .expect("seed browser allow audit");
    let insp_audit = Arc::new(SignedCountingInspector::new(
        &"c".repeat(64),
        "CN=Google LLC",
        "DDFB16CD4931C973A2037D3FC83A4D7D775D05E4",
    ));
    let engine_audit = start_stopped_engine(
        store_audit,
        DaemonConfig {
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::Audit,
            ..DaemonConfig::default()
        },
        Arc::new(FailingPermitDefense) as Arc<dyn ActiveDefenseController>,
        Arc::clone(&insp_audit) as Arc<dyn crate::engine::BinaryInspector>,
    )
    .await;
    let p_audit = ProcessIdentity::new(7202, 700_202);
    send_process_start(&engine_audit, p_audit, chrome_exe);
    let audit_ts = current_unix_ms();
    let calls_audit_start = insp_audit.calls();
    for i in 0..4i64 {
        let _ = engine_audit.process_event_with_lane(
            &SensorEvent::NetworkConnect {
                pid: p_audit.pid,
                protocol: 6,
                dst_ip: IpAddr::V4(Ipv4Addr::new(142, 250, 190, 130)),
                dst_port: 443 + i as u16,
                domain_hint: None,
                timestamp_ms: audit_ts + i,
            },
            EventLane::HighPriority,
        );
    }
    assert_eq!(
        insp_audit.calls(),
        calls_audit_start + 1,
        "Audit mode must engage verified_app_wide_allows fast path without requiring a WFP Permit"
    );
    assert_eq!(engine_audit.verified_app_wide_allows_len(), 1);

    // Part E (`SEC_0001`): Concurrent `delete_policy_rule` completing while an outbound connect
    // is paused inside `inspector.inspect` must never resurrect a stale WFP Permit or fast-path
    // cache entry once `inspect` finishes.
    struct GatedSignedInspector {
        sha256: String,
        signer_subject: String,
        root_thumbprint: String,
        gate_armed: std::sync::atomic::AtomicBool,
        state: std::sync::Mutex<(bool, bool, bool, bool)>, // (entered, released, worker_finished, release_timed_out)
        cv: std::sync::Condvar,
    }
    impl crate::engine::BinaryInspector for GatedSignedInspector {
        fn inspect(&self, exe_path: &str) -> ledr_rules::BinaryIdentity {
            if self.gate_armed.swap(false, Ordering::AcqRel) {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
                guard.0 = true;
                self.cv.notify_all();
                while !guard.1 {
                    let Some(remaining) =
                        deadline.checked_duration_since(std::time::Instant::now())
                    else {
                        guard.3 = true;
                        break;
                    };
                    let (next_guard, wait_res) = self
                        .cv
                        .wait_timeout(guard, remaining)
                        .unwrap_or_else(|e| e.into_inner());
                    guard = next_guard;
                    if !guard.1 && wait_res.timed_out() {
                        guard.3 = true;
                        break;
                    }
                }
            }
            ledr_rules::BinaryIdentity {
                exe_path: exe_path.to_string(),
                sha256: Some(self.sha256.clone()),
                authenticode: Some(AuthenticodeInfo {
                    signer_subject: self.signer_subject.clone(),
                    root_thumbprint: self.root_thumbprint.clone(),
                }),
            }
        }
    }
    struct WorkerFinishedGuard {
        inspector: Arc<GatedSignedInspector>,
    }
    impl Drop for WorkerFinishedGuard {
        fn drop(&mut self) {
            let mut guard = self
                .inspector
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            guard.2 = true;
            self.inspector.cv.notify_all();
        }
    }
    struct ReleaseGateOnDrop {
        inspector: Arc<GatedSignedInspector>,
    }
    impl Drop for ReleaseGateOnDrop {
        fn drop(&mut self) {
            let mut guard = self
                .inspector
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            guard.1 = true;
            self.inspector.cv.notify_all();
        }
    }

    let store_race = LedrStore::open_in_memory().expect("open store race");
    store_race
        .upsert_rule(&browser_rule)
        .expect("seed browser allow race");
    let race_defense = Arc::new(RecordingDefense::new());
    let race_inspector = Arc::new(GatedSignedInspector {
        sha256: "d".repeat(64),
        signer_subject: "CN=Google LLC".to_string(),
        root_thumbprint: "DDFB16CD4931C973A2037D3FC83A4D7D775D05E4".to_string(),
        gate_armed: std::sync::atomic::AtomicBool::new(false),
        state: std::sync::Mutex::new((false, false, false, false)),
        cv: std::sync::Condvar::new(),
    });
    let engine_race = Arc::new(
        start_stopped_engine(
            store_race,
            DaemonConfig {
                outbound_firewall_enabled: true,
                outbound_enforcement_mode: OutboundEnforcementMode::Enforce,
                ..DaemonConfig::default()
            },
            Arc::clone(&race_defense) as Arc<dyn ActiveDefenseController>,
            Arc::clone(&race_inspector) as Arc<dyn crate::engine::BinaryInspector>,
        )
        .await,
    );
    let p_race = ProcessIdentity::new(7203, 700_203);
    send_process_start(&engine_race, p_race, chrome_exe);
    let race_ts = current_unix_ms();

    // Arm the gate for the outbound connect's `inspector.inspect`, run connect on a worker thread.
    race_inspector.gate_armed.store(true, Ordering::Release);
    let release_guard = ReleaseGateOnDrop {
        inspector: Arc::clone(&race_inspector),
    };
    let engine_worker = Arc::clone(&engine_race);
    let inspector_worker = Arc::clone(&race_inspector);
    let connect_thread = std::thread::spawn(move || {
        let _finished_guard = WorkerFinishedGuard {
            inspector: inspector_worker,
        };
        let _ = engine_worker.process_event_with_lane(
            &SensorEvent::NetworkConnect {
                pid: p_race.pid,
                protocol: 6,
                dst_ip: IpAddr::V4(Ipv4Addr::new(142, 250, 190, 140)),
                dst_port: 443,
                domain_hint: None,
                timestamp_ms: race_ts,
            },
            EventLane::HighPriority,
        );
    });

    // Wait with a bounded deadline until the outbound connect is paused inside `inspector.inspect`
    // (or fail immediately if the worker exits without entering `inspector.inspect`).
    {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut guard = race_inspector
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        while !guard.0 && !guard.2 {
            let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) else {
                break;
            };
            let (next_guard, wait_res) = race_inspector
                .cv
                .wait_timeout(guard, remaining)
                .unwrap_or_else(|e| e.into_inner());
            guard = next_guard;
            if wait_res.timed_out() {
                break;
            }
        }
        let entered = guard.0;
        let worker_finished = guard.2;
        drop(guard);
        assert!(
            entered,
            "outbound connect did not enter inspector.inspect before deadline (worker_finished={worker_finished})"
        );
    }

    // Delete the authorizing rule while the connect evaluation holds its stale rule snapshot.
    let (deleted, _report) = engine_race
        .delete_policy_rule(&browser_rule.rule_id)
        .expect("delete browser rule concurrently");
    assert!(deleted, "browser allow rule must be deleted");

    // Release `inspector.inspect` and wait for the in-flight connect evaluation to finish.
    drop(release_guard);
    connect_thread.join().expect("join connect thread");
    let release_timed_out = race_inspector
        .state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .3;
    assert!(
        !release_timed_out,
        "inspector.inspect timed out waiting for gate release (delete_policy_rule must not block on inspector.inspect)"
    );

    assert!(
        !engine_race.has_active_wfp_filter(chrome_exe, None, true),
        "deleted app-wide NetworkAllow must NEVER resurrect a stale WFP Permit after concurrent delete_policy_rule"
    );
    assert_eq!(
        engine_race.verified_app_wide_allows_len(),
        0,
        "deleted app-wide NetworkAllow must NEVER populate verified_app_wide_allows"
    );
}

/// `DAEMON-P4-CMD-01`: Short-lived LOTL chain (`cmd.exe` -> `powershell.exe`) where the initial
/// `ProcessStart` arrives with an empty `command_line`, the process exits (`ProcessStop`), and
/// a delayed enriched `ProcessStart` (`-EncodedCommand`) arrives afterward:
/// - `LEDR-LOTL-001` fires once (`process_suspended == false`),
/// - SQLite `processes` row preserves `exited_at_ms` AND stores the delayed `command_line`,
/// - Preemptive WFP block is NOT re-applied/leaked for the already-exited process.
#[tokio::test]
async fn daemon_p4_cmd_01_exited_short_lived_delayed_cmdline_fires_lotl_without_wfp_leak() {
    let store = LedrStore::open_in_memory().expect("in-memory store");
    let defense = Arc::new(RecordingDefense::new());
    let rules_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/lotl_core.json");
    let sigma = SigmaEngine::from_json_file(&rules_path).expect("load lotl_core.json");

    let engine = DaemonEngine::start_with_dependencies(
        store.clone(),
        sigma,
        EarlyPruner::default(),
        DaemonConfig {
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::Enforce,
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(StubNotifier),
        Arc::new(FixedShaInspector("7".repeat(64))),
    );
    if let Some(h) = engine.worker_handle.lock().await.take() {
        h.abort();
        let _ = h.await;
    }

    let now_ms = current_unix_ms();
    let parent_100ns = 116_444_736_000_000_000u64 + ((now_ms - 2_000) as u64) * 10_000;
    let child_100ns = 116_444_736_000_000_000u64 + ((now_ms - 1_000) as u64) * 10_000;
    let stop_100ns = child_100ns + 400_000; // 40 ms later

    let cmd_parent = ProcessIdentity::new(8100, parent_100ns);
    let ps_child = ProcessIdentity::new(8104, child_100ns);
    let ps_exe = r"C:\Users\Public\Downloads\powershell.exe";
    let ps_cmd = "powershell.exe -EncodedCommand SQBFAFgA";

    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: cmd_parent,
            parent_pid: 4,
            exe_path: r"C:\Windows\System32\cmd.exe".to_string(),
            command_line: "cmd.exe /c powershell.exe".to_string(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );

    // 1. Initial ProcessStart with empty command_line adds preemptive block for HighRiskPath.
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: ps_child,
            parent_pid: cmd_parent.pid,
            exe_path: ps_exe.to_string(),
            command_line: String::new(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    assert_eq!(defense.wfp_blocks_added().len(), 1);
    assert!(engine.has_active_wfp_filter(ps_exe, None, false));
    assert!(store.list_alerts(None, 20).expect("list alerts").is_empty());

    // 2. Short-lived process exits -> preemptive block is removed.
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStop {
            pid: ps_child.pid,
            exit_time_100ns: stop_100ns,
            exit_code: 0,
        },
        EventLane::HighPriority,
    );
    assert!(!engine.has_active_wfp_filter(ps_exe, None, false));

    // 3. Delayed SystemTrace enrichment arrives with full command_line.
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: ps_child,
            parent_pid: cmd_parent.pid,
            exe_path: ps_exe.to_string(),
            command_line: ps_cmd.to_string(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );

    // Preemptive WFP filter must NOT be re-added after exit.
    assert_eq!(defense.wfp_blocks_added().len(), 1);
    assert!(!engine.has_active_wfp_filter(ps_exe, None, false));
    assert!(defense.suspended().is_empty());

    let alerts = store.list_alerts(None, 20).expect("list alerts");
    let lotl = alerts
        .iter()
        .filter(|a| {
            a.rule_id == "LEDR-LOTL-001"
                && a.process_instance_id.as_deref() == Some(ps_child.instance_id().as_str())
        })
        .collect::<Vec<_>>();
    assert_eq!(lotl.len(), 1, "expected 1 LEDR-LOTL-001 alert, got {alerts:?}");
    assert!(!lotl[0].process_suspended);

    store.flush_batch().expect("flush sqlite");
    let snap = store
        .query_flight_recorder(50, Some(&ps_child.instance_id()))
        .expect("query flight recorder");
    let row = snap
        .processes
        .iter()
        .find(|p| p.process_instance_id == ps_child.instance_id())
        .expect("child process row persisted");
    assert_eq!(row.command_line.as_deref(), Some(ps_cmd));
    assert!(row.exited_at_ms.is_some(), "exited_at_ms must stay set");
}

/// `DAEMON-P4-CMD-02`: Even after a short-lived exited process is evicted from `ActiveProcessTable`
/// capacity, a delayed enriched `ProcessStart` does not resurrect it as active, does not fire
/// WFP/MOTW guards, preserves `exited_at_ms` + `command_line` in SQLite, and fires `LEDR-LOTL-001`.
#[tokio::test]
async fn daemon_p4_cmd_02_evicted_exited_process_delayed_cmdline_does_not_resurrect() {
    use crate::process_table::ActiveProcessTable;

    let store = LedrStore::open_in_memory().expect("in-memory store");
    let defense = Arc::new(RecordingDefense::new());
    let rules_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/lotl_core.json");
    let sigma = SigmaEngine::from_json_file(&rules_path).expect("load lotl_core.json");

    let engine = DaemonEngine::start_with_dependencies(
        store.clone(),
        sigma,
        EarlyPruner::default(),
        DaemonConfig {
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::Enforce,
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(StubNotifier),
        Arc::new(FixedShaInspector("8".repeat(64))),
    );
    if let Some(h) = engine.worker_handle.lock().await.take() {
        h.abort();
        let _ = h.await;
    }

    // Replace process_table with a tiny capacity (2) so the exited child is immediately evicted
    // while cmd.exe stays active as parent.
    {
        let mut guard = engine.process_table.lock().unwrap_or_else(|e| e.into_inner());
        *guard = ActiveProcessTable::new(2);
    }

    let now_ms = current_unix_ms();
    let parent_100ns = 116_444_736_000_000_000u64 + ((now_ms - 5_000) as u64) * 10_000;
    let child_100ns = 116_444_736_000_000_000u64 + ((now_ms - 4_000) as u64) * 10_000;
    let stop_100ns = child_100ns + 350_000;
    let filler_100ns = 116_444_736_000_000_000u64 + ((now_ms - 3_000) as u64) * 10_000;

    let cmd_parent = ProcessIdentity::new(8200, parent_100ns);
    let ps_child = ProcessIdentity::new(8204, child_100ns);
    let filler = ProcessIdentity::new(8208, filler_100ns);
    let ps_exe = r"C:\Users\Public\Downloads\powershell.exe";
    let ps_cmd = "powershell.exe -EncodedCommand SQBFAFgA";

    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: cmd_parent,
            parent_pid: 4,
            exe_path: r"C:\Windows\System32\cmd.exe".to_string(),
            command_line: "cmd.exe /c powershell.exe".to_string(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: ps_child,
            parent_pid: cmd_parent.pid,
            exe_path: ps_exe.to_string(),
            command_line: String::new(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStop {
            pid: ps_child.pid,
            exit_time_100ns: stop_100ns,
            exit_code: 0,
        },
        EventLane::HighPriority,
    );
    // Starting filler evicts the exited `ps_child` from capacity-2 `ActiveProcessTable`.
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: filler,
            parent_pid: 4,
            exe_path: r"C:\Windows\System32\notepad.exe".to_string(),
            command_line: "notepad.exe".to_string(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );

    {
        let table = engine.process_table.lock().unwrap_or_else(|e| e.into_inner());
        assert!(table.get_by_instance_id(&ps_child.instance_id()).is_none());
        assert_eq!(table.active_count(), 2);
    }
    assert_eq!(defense.wfp_blocks_added().len(), 1);
    assert!(!engine.has_active_wfp_filter(ps_exe, None, false));

    // Delayed enriched ProcessStart arrives AFTER eviction.
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: ps_child,
            parent_pid: cmd_parent.pid,
            exe_path: ps_exe.to_string(),
            command_line: ps_cmd.to_string(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );

    {
        let table = engine.process_table.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            table.get_by_instance_id(&ps_child.instance_id()).is_none(),
            "evicted exited process must NOT be resurrected into active table"
        );
        assert!(table.lookup_by_pid(ps_child.pid).is_none());
        assert_eq!(table.active_count(), 2);
    }
    assert_eq!(defense.wfp_blocks_added().len(), 1);
    assert!(!engine.has_active_wfp_filter(ps_exe, None, false));

    let alerts = store.list_alerts(None, 20).expect("list alerts");
    let lotl = alerts
        .iter()
        .filter(|a| {
            a.rule_id == "LEDR-LOTL-001"
                && a.process_instance_id.as_deref() == Some(ps_child.instance_id().as_str())
        })
        .collect::<Vec<_>>();
    assert_eq!(lotl.len(), 1, "expected 1 LEDR-LOTL-001 alert, got {alerts:?}");
    assert!(!lotl[0].process_suspended);

    // Duplicate delayed ProcessStart after eviction must NOT emit a duplicate LEDR-LOTL-001 alert.
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: ps_child,
            parent_pid: cmd_parent.pid,
            exe_path: ps_exe.to_string(),
            command_line: ps_cmd.to_string(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    let alerts_after_dup = store.list_alerts(None, 20).expect("list alerts after dup");
    assert_eq!(
        alerts_after_dup
            .iter()
            .filter(|a| {
                a.rule_id == "LEDR-LOTL-001"
                    && a.process_instance_id.as_deref() == Some(ps_child.instance_id().as_str())
            })
            .count(),
        1,
        "evicted_exited must preserve emitted_rule_ids across duplicate delayed ProcessStart"
    );

    // Unverified `pid:0` entry that exits and is evicted must NEVER poison future `pid:0` starts.
    let unverified_pid = 8299;
    let unverified_id = ProcessIdentity::new(unverified_pid, 0);
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: unverified_id,
            parent_pid: 4,
            exe_path: r"C:\Tools\tmp.exe".to_string(),
            command_line: "tmp.exe".to_string(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStop {
            pid: unverified_pid,
            exit_time_100ns: 116_444_736_000_000_000u64 + ((now_ms + 500) as u64) * 10_000,
            exit_code: 0,
        },
        EventLane::HighPriority,
    );
    // Evict unverified_id by inserting another active process into capacity-2 table.
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: ProcessIdentity::new(8296, filler_100ns + 10_000),
            parent_pid: 4,
            exe_path: r"C:\Windows\System32\notepad.exe".to_string(),
            command_line: "notepad.exe".to_string(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    {
        let table = engine.process_table.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            table.get_by_instance_id(&unverified_id.instance_id()).is_none(),
            "exited pid:0 entry must be evicted before testing reuse"
        );
    }
    // Reusing `pid:0` for a HighRiskPath binary must register normally and apply preemptive WFP block.
    let reused_unverified_exe = r"C:\Users\Public\Downloads\reused_zero.exe";
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: unverified_id,
            parent_pid: 4,
            exe_path: reused_unverified_exe.to_string(),
            command_line: "reused_zero.exe".to_string(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    {
        let table = engine.process_table.lock().unwrap_or_else(|e| e.into_inner());
        let entry = table
            .get_by_instance_id(&unverified_id.instance_id())
            .expect("new pid:0 process must be tracked as active");
        assert_eq!(entry.exe_path.as_ref(), reused_unverified_exe);
        assert!(entry.exited_at_ms.is_none());
    }
    assert!(engine.has_active_wfp_filter(reused_unverified_exe, None, false));

    store.flush_batch().expect("flush sqlite");
    let snap = store
        .query_flight_recorder(50, Some(&ps_child.instance_id()))
        .expect("query flight recorder");
    let row = snap
        .processes
        .iter()
        .find(|p| p.process_instance_id == ps_child.instance_id())
        .expect("evicted child row persisted");
    assert_eq!(row.command_line.as_deref(), Some(ps_cmd));
    assert!(row.exited_at_ms.is_some());
}

/// `DAEMON-P4-CMD-03`: Live process receiving delayed enriched `ProcessStart` (`!upgraded_exe`)
/// updates `command_line` monotonically (non-empty never overwritten by `""`) and sets
/// `skip_launch_guards == true` so WFP/MOTW guards are not re-triggered.
#[tokio::test]
async fn daemon_p4_cmd_03_live_enrichment_monotonic_cmdline_and_skips_redundant_launch_guards() {
    let store = LedrStore::open_in_memory().expect("in-memory store");
    let defense = Arc::new(RecordingDefense::new());
    let engine = start_stopped_engine(
        store.clone(),
        DaemonConfig {
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::Enforce,
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(FixedShaInspector("9".repeat(64))),
    )
    .await;

    let now_ms = current_unix_ms();
    let proc_100ns = 116_444_736_000_000_000u64 + ((now_ms - 1_000) as u64) * 10_000;
    let live_proc = ProcessIdentity::new(8300, proc_100ns);
    let live_exe = r"C:\Users\Public\Downloads\tool.exe";

    // 1. Initial live ProcessStart with empty command_line -> adds 1 preemptive WFP block.
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: live_proc,
            parent_pid: 4,
            exe_path: live_exe.to_string(),
            command_line: String::new(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    assert_eq!(defense.wfp_blocks_added().len(), 1);
    assert!(engine.has_active_wfp_filter(live_exe, None, false));

    // Manually clear the preemptive WFP handle inside firewall to prove the 2nd enrichment
    // `ProcessStart` sets `skip_launch_guards == true` and does NOT call `add_wfp_app_rule` again.
    {
        let mut fw = engine.firewall.lock().unwrap_or_else(|e| e.into_inner());
        fw.remove_preemptive_block_if_unused(live_exe, &*engine.defense);
    }
    assert!(!engine.has_active_wfp_filter(live_exe, None, false));

    // Verify table resolution sets skip_launch_guards=true on !upgraded_exe enrichment,
    // and check monotonic command_line update.
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: live_proc,
            parent_pid: 4,
            exe_path: live_exe.to_string(),
            command_line: "tool.exe --enriched".to_string(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    assert_eq!(
        defense.wfp_blocks_added().len(),
        1,
        "2nd ProcessStart with !upgraded_exe must skip preemptive WFP re-registration"
    );
    assert!(!engine.has_active_wfp_filter(live_exe, None, false));

    // 3. Subsequent stale ProcessStart with empty command_line through the full engine pipeline
    // must NEVER clobber existing cmdline in memory or SQLite and must keep skip_launch_guards.
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: live_proc,
            parent_pid: 4,
            exe_path: live_exe.to_string(),
            command_line: String::new(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    assert_eq!(defense.wfp_blocks_added().len(), 1);
    assert!(!engine.has_active_wfp_filter(live_exe, None, false));

    {
        let table = engine.process_table.lock().unwrap_or_else(|e| e.into_inner());
        let entry = table
            .get_by_instance_id(&live_proc.instance_id())
            .expect("live entry still present");
        assert_eq!(entry.command_line, "tool.exe --enriched");
        assert!(entry.exited_at_ms.is_none());
    }

    store.flush_batch().expect("flush sqlite");
    let snap = store
        .query_flight_recorder(50, Some(&live_proc.instance_id()))
        .expect("query flight recorder");
    let row = snap
        .processes
        .iter()
        .find(|p| p.process_instance_id == live_proc.instance_id())
        .expect("live row persisted");
    assert_eq!(row.command_line.as_deref(), Some("tool.exe --enriched"));
}

/// `DAEMON-P4-CMD-04`: When BOTH the parent (`cmd.exe`) and short-lived child (`powershell.exe`)
/// exit and are evicted from `ActiveProcessTable` before the delayed enriched `ProcessStart`
/// arrives, bounded evicted history restores `parent_instance_id` and `parent_exe_path` so
/// `LEDR-LOTL-001` still fires exactly once without resurrecting either entry or leaking WFP rules.
#[tokio::test]
async fn daemon_p4_cmd_04_evicted_parent_and_child_delayed_cmdline_fires_lotl_once() {
    use crate::process_table::ActiveProcessTable;

    let store = LedrStore::open_in_memory().expect("in-memory store");
    let defense = Arc::new(RecordingDefense::new());
    let rules_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/lotl_core.json");
    let sigma = SigmaEngine::from_json_file(&rules_path).expect("load lotl_core.json");

    let engine = DaemonEngine::start_with_dependencies(
        store.clone(),
        sigma,
        EarlyPruner::default(),
        DaemonConfig {
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::Enforce,
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(StubNotifier),
        Arc::new(FixedShaInspector("a".repeat(64))),
    );
    if let Some(h) = engine.worker_handle.lock().await.take() {
        h.abort();
        let _ = h.await;
    }

    {
        let mut guard = engine.process_table.lock().unwrap_or_else(|e| e.into_inner());
        *guard = ActiveProcessTable::new(2);
    }

    let now_ms = current_unix_ms();
    let parent_100ns = 116_444_736_000_000_000u64 + ((now_ms - 6_000) as u64) * 10_000;
    let child_100ns = 116_444_736_000_000_000u64 + ((now_ms - 5_000) as u64) * 10_000;
    let parent_stop_100ns = child_100ns + 200_000;
    let child_stop_100ns = child_100ns + 400_000;
    let filler1_100ns = 116_444_736_000_000_000u64 + ((now_ms - 3_000) as u64) * 10_000;
    let filler2_100ns = 116_444_736_000_000_000u64 + ((now_ms - 2_000) as u64) * 10_000;

    let cmd_parent = ProcessIdentity::new(8400, parent_100ns);
    let ps_child = ProcessIdentity::new(8404, child_100ns);
    let filler1 = ProcessIdentity::new(8408, filler1_100ns);
    let filler2 = ProcessIdentity::new(8412, filler2_100ns);
    let ps_exe = r"C:\Users\Public\Downloads\powershell.exe";
    let ps_cmd = "powershell.exe -EncodedCommand SQBFAFgA";

    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: cmd_parent,
            parent_pid: 4,
            exe_path: r"C:\Windows\System32\cmd.exe".to_string(),
            command_line: "cmd.exe /c powershell.exe".to_string(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: ps_child,
            parent_pid: cmd_parent.pid,
            exe_path: ps_exe.to_string(),
            command_line: String::new(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStop {
            pid: cmd_parent.pid,
            exit_time_100ns: parent_stop_100ns,
            exit_code: 0,
        },
        EventLane::HighPriority,
    );
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStop {
            pid: ps_child.pid,
            exit_time_100ns: child_stop_100ns,
            exit_code: 0,
        },
        EventLane::HighPriority,
    );

    // Evict BOTH cmd_parent and ps_child from the capacity-2 ActiveProcessTable.
    for (ident, name) in [(filler1, "notepad.exe"), (filler2, "calc.exe")] {
        let _ = engine.process_event_with_lane(
            &SensorEvent::ProcessStart {
                identity: ident,
                parent_pid: 4,
                exe_path: format!(r"C:\Windows\System32\{name}"),
                command_line: name.to_string(),
                user_sid: None,
            },
            EventLane::HighPriority,
        );
    }

    {
        let table = engine.process_table.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            table.get_by_instance_id(&cmd_parent.instance_id()).is_none(),
            "parent cmd.exe must be evicted from active table"
        );
        assert!(
            table.get_by_instance_id(&ps_child.instance_id()).is_none(),
            "child powershell.exe must be evicted from active table"
        );
        assert_eq!(table.active_count(), 2);
    }
    assert_eq!(defense.wfp_blocks_added().len(), 1);
    assert!(!engine.has_active_wfp_filter(ps_exe, None, false));

    // Delayed enriched ProcessStart arrives AFTER both parent and child were evicted.
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: ps_child,
            parent_pid: cmd_parent.pid,
            exe_path: ps_exe.to_string(),
            command_line: ps_cmd.to_string(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );

    {
        let table = engine.process_table.lock().unwrap_or_else(|e| e.into_inner());
        assert!(table.get_by_instance_id(&cmd_parent.instance_id()).is_none());
        assert!(table.get_by_instance_id(&ps_child.instance_id()).is_none());
        assert_eq!(table.active_count(), 2);
    }
    assert_eq!(defense.wfp_blocks_added().len(), 1);
    assert!(!engine.has_active_wfp_filter(ps_exe, None, false));

    let alerts = store.list_alerts(None, 20).expect("list alerts");
    let lotl = alerts
        .iter()
        .filter(|a| {
            a.rule_id == "LEDR-LOTL-001"
                && a.process_instance_id.as_deref() == Some(ps_child.instance_id().as_str())
        })
        .collect::<Vec<_>>();
    assert_eq!(
        lotl.len(),
        1,
        "expected 1 LEDR-LOTL-001 alert after both parent and child eviction, got {alerts:?}"
    );
    assert!(!lotl[0].process_suspended);
    let ctx: serde_json::Value =
        serde_json::from_str(&lotl[0].context_json).expect("valid alert context_json");
    assert_eq!(
        ctx["parent_exe_path"].as_str(),
        Some(r"C:\Windows\System32\cmd.exe")
    );

    // Duplicate delayed ProcessStart must NOT emit a duplicate LEDR-LOTL-001 alert.
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: ps_child,
            parent_pid: cmd_parent.pid,
            exe_path: ps_exe.to_string(),
            command_line: ps_cmd.to_string(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    let alerts_after_dup = store.list_alerts(None, 20).expect("list alerts after dup");
    assert_eq!(
        alerts_after_dup
            .iter()
            .filter(|a| {
                a.rule_id == "LEDR-LOTL-001"
                    && a.process_instance_id.as_deref() == Some(ps_child.instance_id().as_str())
            })
            .count(),
        1,
        "duplicate delayed ProcessStart after parent+child eviction must not double-alert"
    );

    store.flush_batch().expect("flush sqlite");
    let snap = store
        .query_flight_recorder(50, Some(&ps_child.instance_id()))
        .expect("query flight recorder");
    let row = snap
        .processes
        .iter()
        .find(|p| p.process_instance_id == ps_child.instance_id())
        .expect("evicted child row persisted");
    assert_eq!(row.command_line.as_deref(), Some(ps_cmd));
    assert_eq!(
        row.parent_instance_id.as_deref(),
        Some(cmd_parent.instance_id().as_str())
    );
    assert!(row.exited_at_ms.is_some());
}

/// `DAEMON-P4-CMD-05`: When `CanaryFileAccess` arrives BEFORE `ProcessStart` for a high-risk
/// binary, `finalize_canary_backfill` immediately applies preemptive WFP launch guards and marks
/// `launch_guards_applied = true` so subsequent `ProcessStart` does not redundantly re-register;
/// and defense-in-depth `launch_guards_applied == false` ensures any pre-existing table entry
/// without applied guards still receives launch guards on `ProcessStart`.
#[tokio::test]
async fn daemon_p4_cmd_05_canary_backfill_before_process_start_applies_launch_guards() {
    let store = LedrStore::open_in_memory().expect("in-memory store");
    let defense = Arc::new(RecordingDefense::new());

    let now_ms = current_unix_ms();
    let canary_proc_100ns = 116_444_736_000_000_000u64 + ((now_ms - 1_000) as u64) * 10_000;
    let pre_reg_100ns = 116_444_736_000_000_000u64 + ((now_ms - 500) as u64) * 10_000;

    let canary_pid = 8500u32;
    let canary_ident = ProcessIdentity::new(canary_pid, canary_proc_100ns);
    let canary_exe = r"C:\Users\Public\Downloads\canary_first.exe";
    let empty_exe_canary_pid = 8512u32;
    let empty_exe_canary_100ns = 116_444_736_000_000_000u64 + ((now_ms - 400) as u64) * 10_000;
    let empty_exe_canary_ident = ProcessIdentity::new(empty_exe_canary_pid, empty_exe_canary_100ns);
    let empty_exe_canary_path = r"C:\Users\Public\Downloads\empty_live_exe_canary.exe";

    let live_inspector = Arc::new(MapLiveProcessInspector::new([
        (
            canary_pid,
            ledr_sensor_win::etw::LiveProcessInfo {
                create_time_100ns: canary_proc_100ns,
                exe_path: Some(canary_exe.to_string()),
                command_line: Some("canary_first.exe --steal".to_string()),
                package_family_name: None,
                package_sid: None,
            },
        ),
        (
            empty_exe_canary_pid,
            ledr_sensor_win::etw::LiveProcessInfo {
                create_time_100ns: empty_exe_canary_100ns,
                exe_path: None,
                command_line: None,
                package_family_name: None,
                package_sid: None,
            },
        ),
    ]));

    let engine = start_stopped_engine_with_live_inspector(
        store.clone(),
        DaemonConfig {
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::Enforce,
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(FixedShaInspector("b".repeat(64))),
        Arc::clone(&live_inspector) as Arc<dyn crate::engine::LiveProcessInspector>,
    )
    .await;

    // 1. CanaryFileAccess arrives BEFORE ProcessStart -> on-demand backfill registers process
    //    AND immediately applies preemptive WFP launch guard.
    let _ = engine.process_event_with_lane(
        &SensorEvent::CanaryFileAccess {
            pid: canary_pid,
            target_path: r"C:\Users\Alice\Documents\_ledr_canary_01.txt".to_string(),
            category: CanaryCategory::Honeypot,
            access_mask: 0x0000_0002,
            is_write_or_delete: true,
            timestamp_ms: now_ms,
        },
        EventLane::HighPriority,
    );

    assert_eq!(
        defense.wfp_blocks_added().len(),
        1,
        "canary backfill must immediately apply preemptive WFP block for HighRiskPath"
    );
    assert!(
        engine.has_active_wfp_filter(canary_exe, None, false),
        "HighRiskPath process backfilled via canary must be blocked before ProcessStart arrives"
    );
    {
        let table = engine.process_table.lock().unwrap_or_else(|e| e.into_inner());
        let entry = table
            .get_by_instance_id(&canary_ident.instance_id())
            .expect("canary-backfilled entry present");
        assert!(
            entry.launch_guards_applied,
            "finalize_canary_backfill must mark launch_guards_applied = true"
        );
    }

    // 2. Subsequent real ProcessStart sees `launch_guards_applied == true && !upgraded_exe`
    //    and skips redundant WFP re-registration while preserving the active block.
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: canary_ident,
            parent_pid: 4,
            exe_path: canary_exe.to_string(),
            command_line: "canary_first.exe --steal".to_string(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    assert_eq!(
        defense.wfp_blocks_added().len(),
        1,
        "ProcessStart after canary backfill must not redundantly re-add WFP block"
    );
    assert!(engine.has_active_wfp_filter(canary_exe, None, false));

    // 3. Defense-in-depth: if an active entry exists in ActiveProcessTable with exe_path set
    //    but `launch_guards_applied == false`, arriving ProcessStart must NOT skip launch guards.
    let pre_reg_ident = ProcessIdentity::new(8504, pre_reg_100ns);
    let pre_reg_exe = r"C:\Users\Public\Downloads\pre_registered_no_guards.exe";
    {
        let mut table = engine.process_table.lock().unwrap_or_else(|e| e.into_inner());
        let res = table.on_process_start(
            pre_reg_ident,
            4,
            pre_reg_exe.to_string(),
            String::new(),
            None,
            now_ms - 500,
        );
        assert!(!res.skip_launch_guards);
        assert!(!table
            .get_by_instance_id(&pre_reg_ident.instance_id())
            .expect("pre-registered entry present")
            .launch_guards_applied);
    }
    assert!(!engine.has_active_wfp_filter(pre_reg_exe, None, false));

    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: pre_reg_ident,
            parent_pid: 4,
            exe_path: pre_reg_exe.to_string(),
            command_line: "pre_registered_no_guards.exe --run".to_string(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    assert_eq!(
        defense.wfp_blocks_added().len(),
        2,
        "ProcessStart must apply launch guards when launch_guards_applied was false"
    );
    assert!(engine.has_active_wfp_filter(pre_reg_exe, None, false));
    {
        let table = engine.process_table.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            table
                .get_by_instance_id(&pre_reg_ident.instance_id())
                .expect("pre-registered entry present")
                .launch_guards_applied
        );
    }

    // 4. Non-enriching `pid:0` snapshot (`skip_store_ingest == true`, `skip_launch_guards == false`)
    //    for an active verified entry with `launch_guards_applied == false` MUST still apply
    //    preemptive WFP launch guards and mark `launch_guards_applied = true`.
    let snap_pid = 8508u32;
    let snap_ident = ProcessIdentity::new(
        snap_pid,
        116_444_736_000_000_000u64 + ((now_ms - 450) as u64) * 10_000,
    );
    let snap_exe = r"C:\Users\Public\Downloads\snap_unapplied_guards.exe";
    {
        let mut table = engine.process_table.lock().unwrap_or_else(|e| e.into_inner());
        let res = table.on_process_start(
            snap_ident,
            4,
            snap_exe.to_string(),
            "snap_unapplied_guards.exe".to_string(),
            Some("S-1-5-21-42".to_string()),
            now_ms - 450,
        );
        assert!(!res.skip_launch_guards);
    }
    assert!(!engine.has_active_wfp_filter(snap_exe, None, false));
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: ProcessIdentity::new(snap_pid, 0),
            parent_pid: 4,
            exe_path: snap_exe.to_string(),
            command_line: "snap_unapplied_guards.exe".to_string(),
            user_sid: Some("S-1-5-21-42".to_string()),
        },
        EventLane::HighPriority,
    );
    assert_eq!(
        defense.wfp_blocks_added().len(),
        3,
        "non-enriching pid:0 snapshot must still apply launch guards when launch_guards_applied was false"
    );
    assert!(engine.has_active_wfp_filter(snap_exe, None, false));
    {
        let table = engine.process_table.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            table
                .get_by_instance_id(&snap_ident.instance_id())
                .expect("snap entry present")
                .launch_guards_applied
        );
    }

    // 5. Canary backfill with `live.exe_path == None` (empty exe_path) must NOT mark
    //    `launch_guards_applied = true`; subsequent `ProcessStart` with HighRiskPath applies WFP.
    let _ = engine.process_event_with_lane(
        &SensorEvent::CanaryFileAccess {
            pid: empty_exe_canary_pid,
            target_path: r"C:\Users\Alice\Documents\_ledr_canary_02.txt".to_string(),
            category: CanaryCategory::Honeypot,
            access_mask: 0x0000_0002,
            is_write_or_delete: true,
            timestamp_ms: now_ms,
        },
        EventLane::HighPriority,
    );
    assert_eq!(defense.wfp_blocks_added().len(), 3);
    {
        let table = engine.process_table.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            !table
                .get_by_instance_id(&empty_exe_canary_ident.instance_id())
                .expect("empty-exe canary entry present")
                .launch_guards_applied,
            "empty exe_path backfill must leave launch_guards_applied = false"
        );
    }
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: empty_exe_canary_ident,
            parent_pid: 4,
            exe_path: empty_exe_canary_path.to_string(),
            command_line: "empty_live_exe_canary.exe".to_string(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    assert_eq!(
        defense.wfp_blocks_added().len(),
        4,
        "ProcessStart upgrading empty exe_path after canary backfill must apply WFP block"
    );
    assert!(engine.has_active_wfp_filter(empty_exe_canary_path, None, false));
    {
        let table = engine.process_table.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            table
                .get_by_instance_id(&empty_exe_canary_ident.instance_id())
                .expect("empty-exe canary entry present")
                .launch_guards_applied
        );
    }
}

/// `DAEMON-P4-CMD-04b`: Oversized evicted parent `command_line` (> 4096 bytes) must be omitted
/// from `ParentCommandLine` evaluation on BOTH normal eviction and delayed enrichment of an
/// evicted parent so Sigma `endswith` rules never false-positive at the truncation boundary,
/// while within-budget evicted parent `command_line` still matches normally.
#[tokio::test]
async fn daemon_p4_cmd_04b_evicted_oversized_parent_cmdline_omitted_prevents_sigma_endswith_fp() {
    use crate::process_table::ActiveProcessTable;
    use ledr_rules::{FieldCondition, MatchModifier, SigmaField, SigmaRule};

    let store = LedrStore::open_in_memory().expect("in-memory store");
    let defense = Arc::new(RecordingDefense::new());
    let rule = SigmaRule {
        id: "TEST-PARENT-ENDSWITH-001".to_string(),
        title: "Parent CommandLine EndsWith Encoded".to_string(),
        severity: AlertSeverity::High,
        description: None,
        conditions: vec![
            FieldCondition {
                field: SigmaField::ParentCommandLine,
                modifier: MatchModifier::EndsWith,
                values: vec![" --encoded".to_string()],
            },
            FieldCondition {
                field: SigmaField::Image,
                modifier: MatchModifier::EndsWith,
                values: vec!["\\powershell.exe".to_string()],
            },
            FieldCondition {
                field: SigmaField::CommandLine,
                modifier: MatchModifier::Contains,
                values: vec!["-NoProfile".to_string()],
            },
        ],
    };
    let sigma = SigmaEngine::from_rules(vec![rule]).expect("compile test sigma rule");

    let engine = DaemonEngine::start_with_dependencies(
        store.clone(),
        sigma,
        EarlyPruner::default(),
        DaemonConfig::default(),
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(StubNotifier),
        Arc::new(FixedShaInspector("c".repeat(64))),
    );
    if let Some(h) = engine.worker_handle.lock().await.take() {
        h.abort();
        let _ = h.await;
    }
    {
        let mut guard = engine.process_table.lock().unwrap_or_else(|e| e.into_inner());
        *guard = ActiveProcessTable::new(2);
    }

    let now_ms = current_unix_ms();
    let ts_100ns = |offset_ms: i64| 116_444_736_000_000_000u64 + ((now_ms + offset_ms) as u64) * 10_000;
    let ps_exe = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    let cmd_exe = r"C:\Windows\System32\cmd.exe";

    // Build an oversized command line (> 4096 bytes) whose first 4096 bytes end with " --encoded"
    // followed by " --profile normal". Truncation at 4096 bytes would falsely satisfy EndsWith.
    let suffix = " --encoded";
    let oversized_parent_cmd = format!("{}{} --profile normal", "x".repeat(4096 - suffix.len()), suffix);
    assert!(oversized_parent_cmd.len() > 4096);
    assert!(oversized_parent_cmd[..4096].ends_with(suffix));

    // Case A: Normal eviction of parent with oversized command_line.
    let p_a = ProcessIdentity::new(8600, ts_100ns(-9_000));
    let c_a = ProcessIdentity::new(8604, ts_100ns(-8_500));
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: p_a,
            parent_pid: 4,
            exe_path: cmd_exe.to_string(),
            command_line: oversized_parent_cmd.clone(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: c_a,
            parent_pid: p_a.pid,
            exe_path: ps_exe.to_string(),
            command_line: String::new(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStop {
            pid: p_a.pid,
            exit_time_100ns: ts_100ns(-8_400),
            exit_code: 0,
        },
        EventLane::HighPriority,
    );
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStop {
            pid: c_a.pid,
            exit_time_100ns: ts_100ns(-8_300),
            exit_code: 0,
        },
        EventLane::HighPriority,
    );

    // Case B: Parent evicted with empty command_line, later enriched with oversized command_line.
    let p_b = ProcessIdentity::new(8608, ts_100ns(-7_000));
    let c_b = ProcessIdentity::new(8612, ts_100ns(-6_500));
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: p_b,
            parent_pid: 4,
            exe_path: cmd_exe.to_string(),
            command_line: String::new(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: c_b,
            parent_pid: p_b.pid,
            exe_path: ps_exe.to_string(),
            command_line: String::new(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStop {
            pid: p_b.pid,
            exit_time_100ns: ts_100ns(-6_400),
            exit_code: 0,
        },
        EventLane::HighPriority,
    );
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStop {
            pid: c_b.pid,
            exit_time_100ns: ts_100ns(-6_300),
            exit_code: 0,
        },
        EventLane::HighPriority,
    );

    // Case C (control): Parent evicted with within-budget command_line truly ending with " --encoded".
    let p_c = ProcessIdentity::new(8616, ts_100ns(-5_000));
    let c_c = ProcessIdentity::new(8620, ts_100ns(-4_500));
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: p_c,
            parent_pid: 4,
            exe_path: cmd_exe.to_string(),
            command_line: "cmd.exe /c powershell.exe --encoded".to_string(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: c_c,
            parent_pid: p_c.pid,
            exe_path: ps_exe.to_string(),
            command_line: String::new(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStop {
            pid: p_c.pid,
            exit_time_100ns: ts_100ns(-4_400),
            exit_code: 0,
        },
        EventLane::HighPriority,
    );
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStop {
            pid: c_c.pid,
            exit_time_100ns: ts_100ns(-4_300),
            exit_code: 0,
        },
        EventLane::HighPriority,
    );

    // Evict Case C as well so all 3 parent+child pairs are in `evicted_exited`.
    for (pid, off) in [(8624, -2_000), (8628, -1_500)] {
        let _ = engine.process_event_with_lane(
            &SensorEvent::ProcessStart {
                identity: ProcessIdentity::new(pid, ts_100ns(off)),
                parent_pid: 4,
                exe_path: r"C:\Windows\System32\notepad.exe".to_string(),
                command_line: "notepad.exe".to_string(),
                user_sid: None,
            },
            EventLane::HighPriority,
        );
    }

    // Delayed enrichment on Case A child -> must NOT false-positive on truncated boundary.
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: c_a,
            parent_pid: p_a.pid,
            exe_path: ps_exe.to_string(),
            command_line: "powershell.exe -NoProfile".to_string(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );

    // Delayed oversized enrichment on Case B parent, then delayed enrichment on Case B child ->
    // must NOT false-positive either.
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: p_b,
            parent_pid: 4,
            exe_path: cmd_exe.to_string(),
            command_line: oversized_parent_cmd,
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: c_b,
            parent_pid: p_b.pid,
            exe_path: ps_exe.to_string(),
            command_line: "powershell.exe -NoProfile".to_string(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );

    let alerts_before_control = store.list_alerts(None, 20).expect("list alerts");
    assert!(
        alerts_before_control.is_empty(),
        "oversized evicted parent command_line must not trigger EndsWith false positive: {:?}",
        alerts_before_control
    );

    // Control Case C: within-budget evicted parent command_line truly ending in " --encoded" fires once.
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity: c_c,
            parent_pid: p_c.pid,
            exe_path: ps_exe.to_string(),
            command_line: "powershell.exe -NoProfile".to_string(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
    let alerts_after_control = store.list_alerts(None, 20).expect("list alerts");
    assert_eq!(alerts_after_control.len(), 1);
    assert_eq!(alerts_after_control[0].rule_id, "TEST-PARENT-ENDSWITH-001");
    assert_eq!(
        alerts_after_control[0].process_instance_id.as_deref(),
        Some(c_c.instance_id().as_str())
    );
}

/// `DAEMON-P4-CMD-06`: When `CanaryFileAccess` arrives BEFORE `ProcessStart` for a normal-folder
/// (non-HighRiskPath) binary with MOTW whose ADS resolution exceeds `motw_sync_wait_budget_ms`,
/// `backfill_canary_process_context_if_missing_async` completes without stalling, and once the
/// MOTW worker finishes, `apply_late_motw_attribution` applies the preemptive WFP block and
/// backfills SQLite `origin_url`.
#[tokio::test]
async fn daemon_p4_cmd_06_canary_first_delayed_motw_exceeding_budget_applies_wfp_for_normal_folder()
{
    use std::sync::atomic::AtomicBool;
    use std::sync::Condvar;
    use std::time::Duration;

    use crate::engine::MotwInspector;
    use ledr_sensor_win::MotwZoneInfo;

    struct GatedMotwInspector {
        entered: Arc<AtomicBool>,
        released: Arc<(Mutex<bool>, Condvar)>,
        zone: MotwZoneInfo,
    }

    impl MotwInspector for GatedMotwInspector {
        fn read_zone_identifier(&self, _path: &Path) -> Option<MotwZoneInfo> {
            self.entered.store(true, Ordering::Release);
            {
                let (lock, cvar) = &*self.released;
                let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
                while !*guard {
                    guard = cvar.wait(guard).unwrap_or_else(|e| e.into_inner());
                }
            }
            Some(self.zone.clone())
        }
    }

    struct ReleaseOnDrop(Arc<(Mutex<bool>, Condvar)>);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            let (lock, cvar) = &*self.0;
            let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
            *guard = true;
            cvar.notify_all();
        }
    }

    let entered = Arc::new(AtomicBool::new(false));
    let released = Arc::new((Mutex::new(false), Condvar::new()));
    let _release_guard = ReleaseOnDrop(Arc::clone(&released));

    let motw_url = "https://downloads.example.invalid/moved_canary_app.exe";
    let gated_motw = Arc::new(GatedMotwInspector {
        entered: Arc::clone(&entered),
        released: Arc::clone(&released),
        zone: MotwZoneInfo {
            zone_id: 3,
            host_url: Some(motw_url.to_string()),
            referrer_url: Some("https://portal.example.invalid/".to_string()),
        },
    });

    let store = LedrStore::open_in_memory().expect("in-memory store");
    let defense = Arc::new(RecordingDefense::new());
    let now_ms = current_unix_ms();
    let proc_100ns = 116_444_736_000_000_000u64 + ((now_ms - 1_000) as u64) * 10_000;
    let pid = 8700u32;
    let ident = ProcessIdentity::new(pid, proc_100ns);
    // Normal folder (GeneralUnknown, NOT HighRiskPath): preemptive WFP block depends solely on MOTW.
    let normal_exe = r"C:\Tools\moved_canary_app.exe";

    let live_inspector = Arc::new(MapLiveProcessInspector::new([(
        pid,
        ledr_sensor_win::etw::LiveProcessInfo {
            create_time_100ns: proc_100ns,
            exe_path: Some(normal_exe.to_string()),
            command_line: Some("moved_canary_app.exe --quiet".to_string()),
            package_family_name: None,
            package_sid: None,
        },
    )]));

    let engine = DaemonEngine::start_with_motw_inspector(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::Enforce,
            motw_sync_wait_budget_ms: 20,
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(StubNotifier),
        Arc::new(FixedShaInspector("d".repeat(64))),
        live_inspector,
        gated_motw,
    );

    let sender = engine.sender();
    // 1. CanaryFileAccess arrives BEFORE ProcessStart.
    sender
        .send(SensorEvent::CanaryFileAccess {
            pid,
            target_path: r"C:\Users\Alice\Documents\_ledr_canary_03.txt".to_string(),
            category: CanaryCategory::Honeypot,
            access_mask: 0x0000_0002,
            is_write_or_delete: true,
            timestamp_ms: now_ms,
        })
        .await
        .expect("send CanaryFileAccess");

    // Confirm the MOTW worker entered `read_zone_identifier` (and is blocked on our gate).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if entered.load(Ordering::Acquire) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "MOTW worker must enter gated read_zone_identifier"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // Even while MOTW is blocked beyond the 20 ms budget, canary backfill + suspension must finish.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if !defense.suspended().is_empty()
            && engine.high_priority_processed.load(Ordering::Relaxed) >= 1
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "canary event must complete past MOTW wait budget without stalling"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        !engine.has_active_wfp_filter(normal_exe, None, false),
        "normal-folder binary must not have WFP block before delayed MOTW completes"
    );

    // 2. Subsequent real ProcessStart arrives while delayed MOTW is still in flight.
    sender
        .send(SensorEvent::ProcessStart {
            identity: ident,
            parent_pid: 4,
            exe_path: normal_exe.to_string(),
            command_line: "moved_canary_app.exe --quiet".to_string(),
            user_sid: None,
        })
        .await
        .expect("send ProcessStart");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if engine.high_priority_processed.load(Ordering::Relaxed) >= 2 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "ProcessStart must complete while MOTW is still gated"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // 3. Release MOTW gate -> late attribution must apply preemptive WFP block & backfill SQLite.
    {
        let (lock, cvar) = &*released;
        let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        *guard = true;
        cvar.notify_all();
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if engine.has_active_wfp_filter(normal_exe, None, false) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "delayed MOTW completion must apply preemptive WFP block for normal-folder binary"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert_eq!(
        defense.wfp_blocks_added().len(),
        1,
        "delayed MOTW must apply preemptive WFP block exactly once"
    );

    engine.shutdown_and_flush().await.expect("shutdown engine");

    let snap = store
        .query_flight_recorder(50, Some(&ident.instance_id()))
        .expect("query flight recorder");
    let row = snap
        .processes
        .iter()
        .find(|p| p.process_instance_id == ident.instance_id())
        .expect("process row persisted");
    assert_eq!(row.origin_url.as_deref(), Some(motw_url));
}

/// Bounded non-blocking probe for `engine.firewall` used by concurrent WFP race regression tests
/// (`PRRT_kwDOVyjVyM66kD-5`). If a regression moves an in-flight `add_wfp_app_rule` call inside
/// `engine.firewall.lock()`, `try_lock()` times out and fails the test cleanly instead of hanging
/// before `ReleaseGatesOnDrop` can release the paused gate.
async fn try_has_active_wfp_filter(
    engine: &DaemonEngine,
    exe_path: &str,
    remote_ip: Option<IpAddr>,
    allow: bool,
    timeout: std::time::Duration,
) -> Result<bool, String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match engine.firewall.try_lock() {
            Ok(fw) => return Ok(fw.has_active_filter(exe_path, remote_ip, allow)),
            Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                return Ok(poisoned
                    .into_inner()
                    .has_active_filter(exe_path, remote_ip, allow));
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(format!(
                        "timed out after {} ms acquiring engine.firewall lock while checking filter for `{exe_path}` (possible lock held across add_wfp_app_rule)",
                        timeout.as_millis()
                    ));
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        }
    }
}

/// `DAEMON-P4-CMD-07`: Concurrent startup snapshot (`seed_processes`) racing with ETW
/// `ProcessStart` + `ProcessStop` for a short-lived `Downloads` executable must never leave a
/// residual preemptive WFP block or leaked BFE handle (`PRRT_kwDOVyjVyM66jl1W`).
///
/// Also verifies that `apply_process_launch_guards`'s active-only entry guard preserves `L-18`
/// MOTW preemptive blocking when `seed_processes` marks `launch_guards_applied = true` first
/// without MOTW and ETW `ProcessStart` subsequently finishes MOTW resolution while still active.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_p4_cmd_07_seed_process_wfp_race_leaves_no_residual_block_and_preserves_motw() {
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::sync::Condvar;
    use std::time::Duration;

    use crate::engine::MotwInspector;
    use ledr_sensor_win::MotwZoneInfo;

    struct Gate {
        entered: AtomicBool,
        released: Mutex<bool>,
        cvar: Condvar,
    }

    impl Gate {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                entered: AtomicBool::new(false),
                released: Mutex::new(false),
                cvar: Condvar::new(),
            })
        }

        fn wait_gate(&self) {
            self.entered.store(true, Ordering::Release);
            let mut guard = self.released.lock().unwrap_or_else(|e| e.into_inner());
            while !*guard {
                guard = self.cvar.wait(guard).unwrap_or_else(|e| e.into_inner());
            }
        }

        fn release(&self) {
            let mut guard = self.released.lock().unwrap_or_else(|e| e.into_inner());
            *guard = true;
            self.cvar.notify_all();
        }

        fn is_entered(&self) -> bool {
            self.entered.load(Ordering::Acquire)
        }
    }

    struct ReleaseGatesOnDrop(Vec<Arc<Gate>>);
    impl Drop for ReleaseGatesOnDrop {
        fn drop(&mut self) {
            for gate in &self.0 {
                gate.release();
            }
        }
    }

    struct DualGatedMotwInspector {
        short_exe_lower: String,
        short_gate: Arc<Gate>,
        normal_exe_lower: String,
        normal_gate: Arc<Gate>,
        normal_zone: MotwZoneInfo,
    }

    impl MotwInspector for DualGatedMotwInspector {
        fn read_zone_identifier(&self, path: &Path) -> Option<MotwZoneInfo> {
            let lower = path.to_string_lossy().to_ascii_lowercase();
            if lower == self.short_exe_lower {
                self.short_gate.wait_gate();
                return None;
            }
            if lower == self.normal_exe_lower {
                self.normal_gate.wait_gate();
                return Some(self.normal_zone.clone());
            }
            None
        }
    }

    struct GatedWfpDefense {
        next_handle: AtomicU64,
        target_exe_lower: String,
        target_add_calls: AtomicUsize,
        first_add_gate: Arc<Gate>,
        active_handles: Mutex<HashSet<u64>>,
        added_for_target: AtomicUsize,
        removed_total: AtomicUsize,
    }

    impl GatedWfpDefense {
        fn new(target_exe: &str, first_add_gate: Arc<Gate>) -> Self {
            Self {
                next_handle: AtomicU64::new(9_000),
                target_exe_lower: target_exe.to_ascii_lowercase(),
                target_add_calls: AtomicUsize::new(0),
                first_add_gate,
                active_handles: Mutex::new(HashSet::new()),
                added_for_target: AtomicUsize::new(0),
                removed_total: AtomicUsize::new(0),
            }
        }

        fn active_handles(&self) -> HashSet<u64> {
            self.active_handles
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
    }

    impl ActiveDefenseController for GatedWfpDefense {
        fn suspend_process(
            &self,
            _target: &ProcessIdentity,
            _include_children: bool,
        ) -> Result<(), String> {
            Ok(())
        }

        fn resume_process(&self, _target: &ProcessIdentity) -> Result<(), String> {
            Ok(())
        }

        fn terminate_process(
            &self,
            _target: &ProcessIdentity,
            _include_children: bool,
        ) -> Result<(), String> {
            Ok(())
        }

        fn add_wfp_app_rule(
            &self,
            exe_path: &Path,
            _remote_ip: Option<IpAddr>,
            allow: bool,
        ) -> Result<u64, String> {
            let lower = exe_path.to_string_lossy().to_ascii_lowercase();
            let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
            // Activate the handle in the mock OS BFE BEFORE pausing at `first_add_gate` so the
            // race matches real `FwpmFilterAdd0` (filter live in OS while unregistered in daemon).
            self.active_handles
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(handle);
            if !allow && lower == self.target_exe_lower {
                self.added_for_target.fetch_add(1, Ordering::Relaxed);
                let call_idx = self.target_add_calls.fetch_add(1, Ordering::AcqRel);
                if call_idx == 0 {
                    // Pause the first add_wfp_app_rule call (from seed_processes on its OS thread)
                    // until ETW ProcessStart + ProcessStop have completed and removed their block.
                    self.first_add_gate.wait_gate();
                }
            }
            Ok(handle)
        }

        fn remove_wfp_rule(&self, filter_id: u64) -> Result<(), String> {
            self.active_handles
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&filter_id);
            self.removed_total.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    let short_exe = r"C:\Users\Alice\Downloads\short_race.exe";
    let normal_motw_exe = r"C:\Tools\race_motw_app.exe";
    let short_motw_gate = Gate::new();
    let normal_motw_gate = Gate::new();
    let seed_wfp_add_gate = Gate::new();
    let _release_all = ReleaseGatesOnDrop(vec![
        Arc::clone(&short_motw_gate),
        Arc::clone(&normal_motw_gate),
        Arc::clone(&seed_wfp_add_gate),
    ]);

    let defense = Arc::new(GatedWfpDefense::new(
        short_exe,
        Arc::clone(&seed_wfp_add_gate),
    ));
    let motw_inspector = Arc::new(DualGatedMotwInspector {
        short_exe_lower: short_exe.to_ascii_lowercase(),
        short_gate: Arc::clone(&short_motw_gate),
        normal_exe_lower: normal_motw_exe.to_ascii_lowercase(),
        normal_gate: Arc::clone(&normal_motw_gate),
        normal_zone: MotwZoneInfo {
            zone_id: 3,
            host_url: Some("https://downloads.example.invalid/race_motw_app.exe".to_string()),
            referrer_url: None,
        },
    });

    let store = LedrStore::open_in_memory().expect("in-memory store");
    let engine = DaemonEngine::start_with_motw_inspector(
        store,
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::Enforce,
            motw_sync_wait_budget_ms: 5_000,
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(StubNotifier),
        Arc::new(FixedShaInspector("e".repeat(64))),
        Arc::new(MapLiveProcessInspector::new([])),
        motw_inspector,
    );

    let sender = engine.sender();
    let now_ms = current_unix_ms();
    let pid1 = 8800u32;
    let create1_100ns = 116_444_736_000_000_000u64 + ((now_ms - 1_000) as u64) * 10_000;
    let ident1 = ProcessIdentity::new(pid1, create1_100ns);

    // --- Part A: seed_processes add_wfp_app_rule pauses until after ETW ProcessStop cleanup ---
    // 1. ETW ProcessStart registers pid1 in process_table (launch_guards_applied = false) and pauses at MOTW.
    sender
        .send(SensorEvent::ProcessStart {
            identity: ident1,
            parent_pid: 4,
            exe_path: short_exe.to_string(),
            command_line: "short_race.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send ETW ProcessStart for short_exe");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !short_motw_gate.is_entered() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "ETW ProcessStart must enter MOTW gate for short_exe"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // 2. Concurrent startup snapshot (create_time_100ns == 0) merges into pid1 and enters add_wfp_app_rule.
    let engine_for_seed = Arc::clone(&engine);
    let seed_handle = std::thread::spawn(move || {
        engine_for_seed.seed_processes(vec![SensorEvent::ProcessStart {
            identity: ProcessIdentity::new(pid1, 0),
            parent_pid: 4,
            exe_path: short_exe.to_string(),
            command_line: "short_race.exe".to_string(),
            user_sid: None,
        }])
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !seed_wfp_add_gate.is_entered() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "seed_processes must enter gated add_wfp_app_rule for short_exe"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(
        defense.active_handles().len(),
        1,
        "handle #1 must already be active in OS BFE before seed_processes commits it to daemon"
    );
    assert!(
        !try_has_active_wfp_filter(&engine, short_exe, None, false, Duration::from_secs(2))
            .await
            .expect("firewall lock must not be held across in-flight add_wfp_app_rule"),
        "handle #1 must not yet be registered in WfpRuleManager while seed_processes is paused"
    );

    // 3. Release ETW MOTW gate -> ETW worker finishes ProcessStart and installs handle #2.
    let hp_before_start1 = engine.high_priority_processed.load(Ordering::Relaxed);
    short_motw_gate.release();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while engine.high_priority_processed.load(Ordering::Relaxed) < hp_before_start1 + 1
        || !try_has_active_wfp_filter(&engine, short_exe, None, false, Duration::from_secs(2))
            .await
            .expect("firewall lock must remain unblocked while seed_processes is paused")
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "ETW ProcessStart must install preemptive WFP block for short_exe"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(
        defense.active_handles().len(),
        2,
        "both uncommitted OS handle #1 and ETW handle #2 must be active in OS BFE"
    );

    // 4. ETW ProcessStop exits pid1 and removes handle #2 while seed_processes is still paused
    //    with handle #1 active in OS BFE but unregistered in WfpRuleManager.
    let hp_before_stop1 = engine.high_priority_processed.load(Ordering::Relaxed);
    sender
        .send(SensorEvent::ProcessStop {
            pid: pid1,
            exit_time_100ns: create1_100ns + 500_000,
            exit_code: 0,
        })
        .await
        .expect("send ETW ProcessStop for short_exe");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while engine.high_priority_processed.load(Ordering::Relaxed) < hp_before_stop1 + 1 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "ETW ProcessStop must finish for short_exe"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        !try_has_active_wfp_filter(&engine, short_exe, None, false, Duration::from_secs(2))
            .await
            .expect("firewall lock must remain unblocked after ETW ProcessStop"),
        "ETW ProcessStop must remove handle #2 before seed_processes resumes"
    );
    assert_eq!(
        defense.active_handles().len(),
        1,
        "uncommitted OS handle #1 must remain active in OS BFE across ETW ProcessStop until seed_processes resumes"
    );

    // 5. Resume seed_processes -> it must observe pid1 exited under `firewall -> process_table`
    //    and remove handle #1 instead of leaving a residual block.
    seed_wfp_add_gate.release();
    let seeded = tokio::task::spawn_blocking(move || seed_handle.join())
        .await
        .expect("join spawn_blocking")
        .expect("seed_processes thread panicked")
        .expect("seed_processes returned error");
    assert_eq!(seeded, 1);

    assert!(
        !try_has_active_wfp_filter(&engine, short_exe, None, false, Duration::from_secs(2))
            .await
            .expect("firewall lock available after seed_processes completes"),
        "delayed seed_processes must not leave a residual preemptive WFP block after ProcessStop"
    );
    assert!(
        defense.active_handles().is_empty(),
        "delayed seed_processes must remove its obsolete BFE handle instead of leaking it"
    );
    assert_eq!(
        defense.added_for_target.load(Ordering::Relaxed),
        2,
        "both seed_processes and ETW ProcessStart must have attempted add_wfp_app_rule"
    );
    assert_eq!(
        defense.removed_total.load(Ordering::Relaxed),
        2,
        "both WFP handles (ETW + obsolete seed handle) must have been removed"
    );

    // --- Part B: active-only entry guard preserves L-18 MOTW when seed_processes runs first ---
    let pid2 = 8801u32;
    let create2_100ns = 116_444_736_000_000_000u64 + ((now_ms + 100) as u64) * 10_000;
    let ident2 = ProcessIdentity::new(pid2, create2_100ns);

    sender
        .send(SensorEvent::ProcessStart {
            identity: ident2,
            parent_pid: 4,
            exe_path: normal_motw_exe.to_string(),
            command_line: "race_motw_app.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send ETW ProcessStart for normal_motw_exe");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !normal_motw_gate.is_entered() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "ETW ProcessStart must enter MOTW gate for normal_motw_exe"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // seed_processes completes first without MOTW, marking launch_guards_applied = true.
    let engine_for_seed2 = Arc::clone(&engine);
    let seeded2 = tokio::task::spawn_blocking(move || {
        engine_for_seed2.seed_processes(vec![SensorEvent::ProcessStart {
            identity: ProcessIdentity::new(pid2, 0),
            parent_pid: 4,
            exe_path: normal_motw_exe.to_string(),
            command_line: "race_motw_app.exe".to_string(),
            user_sid: None,
        }])
    })
    .await
    .expect("join seed2")
    .expect("seed_processes for normal_motw_exe");
    assert_eq!(seeded2, 1);

    {
        let table = engine
            .process_table
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let entry = table
            .get_by_instance_id(&ident2.instance_id())
            .expect("normal_motw_exe entry present");
        assert!(
            entry.launch_guards_applied,
            "seed_processes must mark launch_guards_applied = true"
        );
    }
    assert!(
        !try_has_active_wfp_filter(&engine, normal_motw_exe, None, false, Duration::from_secs(2))
            .await
            .expect("firewall lock available before MOTW resolves"),
        "normal-folder binary must not be blocked before MOTW resolves"
    );

    // Release MOTW gate -> ETW ProcessStart must still apply L-18 preemptive WFP block despite
    // launch_guards_applied already being true.
    let hp_before_motw_release = engine.high_priority_processed.load(Ordering::Relaxed);
    normal_motw_gate.release();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while engine.high_priority_processed.load(Ordering::Relaxed) < hp_before_motw_release + 1 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "ETW ProcessStart must finish after MOTW release for normal_motw_exe"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        try_has_active_wfp_filter(&engine, normal_motw_exe, None, false, Duration::from_secs(2))
            .await
            .expect("firewall lock available after MOTW resolves"),
        "active-only entry guard must preserve L-18 MOTW preemptive WFP block"
    );

    // ProcessStop must clean up the MOTW preemptive block cleanly.
    let hp_before_stop2 = engine.high_priority_processed.load(Ordering::Relaxed);
    sender
        .send(SensorEvent::ProcessStop {
            pid: pid2,
            exit_time_100ns: create2_100ns + 500_000,
            exit_code: 0,
        })
        .await
        .expect("send ProcessStop for normal_motw_exe");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while engine.high_priority_processed.load(Ordering::Relaxed) < hp_before_stop2 + 1 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "ETW ProcessStop must finish for normal_motw_exe"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        !try_has_active_wfp_filter(&engine, normal_motw_exe, None, false, Duration::from_secs(2))
            .await
            .expect("firewall lock available after ProcessStop for normal_motw_exe"),
        "ProcessStop must clean up L-18 MOTW preemptive WFP block"
    );
    assert!(
        defense.active_handles().is_empty(),
        "all BFE handles must be cleaned up after both processes exit"
    );

    engine.shutdown_and_flush().await.expect("shutdown engine");
}

/// `DAEMON-P4-CMD-08`: When `seed_processes` resumes after `ProcessStop` and `remove_wfp_rule`
/// fails transiently for its obsolete OS-active handle (`PRRT_kwDOVyjVyM66j96a`), `WfpRuleManager`
/// retains the handle as a tracked `Preemptive` filter so a subsequent launch does not duplicate
/// the OS filter and the subsequent `ProcessStop` retries removal cleanly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_p4_cmd_08_obsolete_wfp_remove_failure_retained_for_subsequent_cleanup() {
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::sync::Condvar;
    use std::time::Duration;

    use crate::engine::MotwInspector;
    use ledr_sensor_win::MotwZoneInfo;

    struct Gate {
        entered: AtomicBool,
        released: Mutex<bool>,
        cvar: Condvar,
    }

    impl Gate {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                entered: AtomicBool::new(false),
                released: Mutex::new(false),
                cvar: Condvar::new(),
            })
        }

        fn wait_gate(&self) {
            self.entered.store(true, Ordering::Release);
            let mut guard = self.released.lock().unwrap_or_else(|e| e.into_inner());
            while !*guard {
                guard = self.cvar.wait(guard).unwrap_or_else(|e| e.into_inner());
            }
        }

        fn release(&self) {
            let mut guard = self.released.lock().unwrap_or_else(|e| e.into_inner());
            *guard = true;
            self.cvar.notify_all();
        }

        fn is_entered(&self) -> bool {
            self.entered.load(Ordering::Acquire)
        }
    }

    struct ReleaseGatesOnDrop(Vec<Arc<Gate>>);
    impl Drop for ReleaseGatesOnDrop {
        fn drop(&mut self) {
            for gate in &self.0 {
                gate.release();
            }
        }
    }

    struct OnceGatedMotwInspector {
        target_exe_lower: String,
        gate: Arc<Gate>,
        calls: AtomicUsize,
    }

    impl MotwInspector for OnceGatedMotwInspector {
        fn read_zone_identifier(&self, path: &Path) -> Option<MotwZoneInfo> {
            if path.to_string_lossy().to_ascii_lowercase() == self.target_exe_lower
                && self.calls.fetch_add(1, Ordering::AcqRel) == 0
            {
                self.gate.wait_gate();
            }
            None
        }
    }

    struct FaultyGatedWfpDefense {
        next_handle: AtomicU64,
        target_exe_lower: String,
        target_add_calls: AtomicUsize,
        first_add_gate: Arc<Gate>,
        fail_removes: AtomicBool,
        active_handles: Mutex<HashSet<u64>>,
        added_for_target: AtomicUsize,
        remove_failures: AtomicUsize,
        remove_successes: AtomicUsize,
    }

    impl FaultyGatedWfpDefense {
        fn new(target_exe: &str, first_add_gate: Arc<Gate>) -> Self {
            Self {
                next_handle: AtomicU64::new(11_000),
                target_exe_lower: target_exe.to_ascii_lowercase(),
                target_add_calls: AtomicUsize::new(0),
                first_add_gate,
                fail_removes: AtomicBool::new(false),
                active_handles: Mutex::new(HashSet::new()),
                added_for_target: AtomicUsize::new(0),
                remove_failures: AtomicUsize::new(0),
                remove_successes: AtomicUsize::new(0),
            }
        }

        fn active_handles(&self) -> HashSet<u64> {
            self.active_handles
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
    }

    impl ActiveDefenseController for FaultyGatedWfpDefense {
        fn suspend_process(&self, _: &ProcessIdentity, _: bool) -> Result<(), String> {
            Ok(())
        }
        fn resume_process(&self, _: &ProcessIdentity) -> Result<(), String> {
            Ok(())
        }
        fn terminate_process(&self, _: &ProcessIdentity, _: bool) -> Result<(), String> {
            Ok(())
        }

        fn add_wfp_app_rule(
            &self,
            exe_path: &Path,
            _remote_ip: Option<IpAddr>,
            allow: bool,
        ) -> Result<u64, String> {
            let lower = exe_path.to_string_lossy().to_ascii_lowercase();
            let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
            self.active_handles
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(handle);
            if !allow && lower == self.target_exe_lower {
                self.added_for_target.fetch_add(1, Ordering::Relaxed);
                if self.target_add_calls.fetch_add(1, Ordering::AcqRel) == 0 {
                    self.first_add_gate.wait_gate();
                }
            }
            Ok(handle)
        }

        fn remove_wfp_rule(&self, filter_id: u64) -> Result<(), String> {
            if self.fail_removes.load(Ordering::Acquire) {
                self.remove_failures.fetch_add(1, Ordering::Relaxed);
                return Err(format!("transient BFE busy removing {filter_id}"));
            }
            self.active_handles
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&filter_id);
            self.remove_successes.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    let retry_exe = r"C:\Users\Alice\Downloads\retry_remove_race.exe";
    let motw_gate = Gate::new();
    let seed_wfp_gate = Gate::new();
    let _release_all = ReleaseGatesOnDrop(vec![Arc::clone(&motw_gate), Arc::clone(&seed_wfp_gate)]);

    let defense = Arc::new(FaultyGatedWfpDefense::new(
        retry_exe,
        Arc::clone(&seed_wfp_gate),
    ));
    let motw_inspector = Arc::new(OnceGatedMotwInspector {
        target_exe_lower: retry_exe.to_ascii_lowercase(),
        gate: Arc::clone(&motw_gate),
        calls: AtomicUsize::new(0),
    });

    let store = LedrStore::open_in_memory().expect("in-memory store");
    let engine = DaemonEngine::start_with_motw_inspector(
        store,
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::Enforce,
            motw_sync_wait_budget_ms: 5_000,
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(StubNotifier),
        Arc::new(FixedShaInspector("f".repeat(64))),
        Arc::new(MapLiveProcessInspector::new([])),
        motw_inspector,
    );

    let sender = engine.sender();
    let now_ms = current_unix_ms();
    let pid1 = 8810u32;
    let create1_100ns = 116_444_736_000_000_000u64 + ((now_ms - 1_000) as u64) * 10_000;
    let ident1 = ProcessIdentity::new(pid1, create1_100ns);

    sender
        .send(SensorEvent::ProcessStart {
            identity: ident1,
            parent_pid: 4,
            exe_path: retry_exe.to_string(),
            command_line: "retry_remove_race.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send ProcessStart #1");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !motw_gate.is_entered() {
        assert!(tokio::time::Instant::now() < deadline, "MOTW gate entered");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let engine_for_seed = Arc::clone(&engine);
    let seed_handle = std::thread::spawn(move || {
        engine_for_seed.seed_processes(vec![SensorEvent::ProcessStart {
            identity: ProcessIdentity::new(pid1, 0),
            parent_pid: 4,
            exe_path: retry_exe.to_string(),
            command_line: "retry_remove_race.exe".to_string(),
            user_sid: None,
        }])
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !seed_wfp_gate.is_entered() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "seed WFP gate entered"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(
        defense.active_handles().len(),
        1,
        "handle #1 must already be active in OS BFE while seed_processes is paused"
    );
    assert!(
        !try_has_active_wfp_filter(&engine, retry_exe, None, false, Duration::from_secs(2))
            .await
            .expect("firewall lock must not be held across in-flight add_wfp_app_rule"),
        "handle #1 must not yet be registered in WfpRuleManager while seed_processes is paused"
    );

    // Complete ETW ProcessStart #1 and ProcessStop #1 cleanly.
    let hp_before_start1 = engine.high_priority_processed.load(Ordering::Relaxed);
    motw_gate.release();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while engine.high_priority_processed.load(Ordering::Relaxed) < hp_before_start1 + 1
        || !try_has_active_wfp_filter(&engine, retry_exe, None, false, Duration::from_secs(2))
            .await
            .expect("firewall lock must remain unblocked while seed_processes is paused")
    {
        assert!(tokio::time::Instant::now() < deadline, "ETW start #1 done");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let hp_before_stop1 = engine.high_priority_processed.load(Ordering::Relaxed);
    sender
        .send(SensorEvent::ProcessStop {
            pid: pid1,
            exit_time_100ns: create1_100ns + 500_000,
            exit_code: 0,
        })
        .await
        .expect("send ProcessStop #1");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while engine.high_priority_processed.load(Ordering::Relaxed) < hp_before_stop1 + 1 {
        assert!(tokio::time::Instant::now() < deadline, "ETW stop #1 done");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        !try_has_active_wfp_filter(&engine, retry_exe, None, false, Duration::from_secs(2))
            .await
            .expect("firewall lock must remain unblocked after ETW ProcessStop #1")
    );
    assert_eq!(defense.active_handles().len(), 1);

    // Inject transient remove_wfp_rule failure before resuming seed_processes.
    defense.fail_removes.store(true, Ordering::Release);
    seed_wfp_gate.release();
    let seeded = tokio::task::spawn_blocking(move || seed_handle.join())
        .await
        .expect("join spawn_blocking")
        .expect("seed_processes thread panicked")
        .expect("seed_processes returned error");
    assert_eq!(seeded, 1);

    assert!(
        defense.remove_failures.load(Ordering::Relaxed) >= 1,
        "obsolete handle removal failure must have been recorded"
    );
    assert!(
        try_has_active_wfp_filter(&engine, retry_exe, None, false, Duration::from_secs(2))
            .await
            .expect("firewall lock available after seed_processes completes"),
        "failed obsolete handle removal must retain handle in WfpRuleManager for retry"
    );
    assert_eq!(defense.active_handles().len(), 1);

    // Keep `fail_removes == true` while launching ProcessStart #2 so periodic expiry_ticker
    // sweeps cannot race ahead and remove the retained handle before ProcessStart #2 observes
    // and reuses it; then clear `fail_removes` while pid2 is active (so periodic sweeps still
    // must keep it) and verify ProcessStop #2 removes the retained handle cleanly.
    let pid2 = 8811u32;
    let create2_100ns = create1_100ns + 1_000_000;
    let ident2 = ProcessIdentity::new(pid2, create2_100ns);

    let hp_before_start2 = engine.high_priority_processed.load(Ordering::Relaxed);
    sender
        .send(SensorEvent::ProcessStart {
            identity: ident2,
            parent_pid: 4,
            exe_path: retry_exe.to_string(),
            command_line: "retry_remove_race.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send ProcessStart #2");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while engine.high_priority_processed.load(Ordering::Relaxed) < hp_before_start2 + 1 {
        assert!(tokio::time::Instant::now() < deadline, "ETW start #2 done");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(
        defense.added_for_target.load(Ordering::Relaxed),
        2,
        "subsequent launch must reuse the retained handle without creating a duplicate OS filter"
    );

    defense.fail_removes.store(false, Ordering::Release);

    let hp_before_stop2 = engine.high_priority_processed.load(Ordering::Relaxed);
    sender
        .send(SensorEvent::ProcessStop {
            pid: pid2,
            exit_time_100ns: create2_100ns + 500_000,
            exit_code: 0,
        })
        .await
        .expect("send ProcessStop #2");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while engine.high_priority_processed.load(Ordering::Relaxed) < hp_before_stop2 + 1 {
        assert!(tokio::time::Instant::now() < deadline, "ETW stop #2 done");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        !try_has_active_wfp_filter(&engine, retry_exe, None, false, Duration::from_secs(2))
            .await
            .expect("firewall lock available after ProcessStop #2"),
        "subsequent ProcessStop must retry and remove the retained obsolete handle"
    );
    assert!(
        defense.active_handles().is_empty(),
        "all OS BFE handles must be cleared after retry cleanup"
    );
    assert_eq!(defense.remove_successes.load(Ordering::Relaxed), 2);

    engine.shutdown_and_flush().await.expect("shutdown engine");
}

/// `DAEMON-P4-CMD-09`: When a retained unused `Preemptive` WFP block remains after a transient
/// `remove_wfp_rule` failure (`PRRT_kwDOVyjVyM66kD_M`), the `pipeline.rs` `expiry_ticker` periodic
/// sweep retries removal automatically once BFE recovers—without requiring a process relaunch or
/// an app-wide `NetworkAllow` reconciliation—while preserving active processes' `Preemptive`
/// blocks across the same sweeps.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_p4_cmd_09_periodic_sweep_retries_retained_obsolete_preemptive_block() {
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::sync::Condvar;
    use std::time::Duration;

    use crate::engine::MotwInspector;
    use ledr_sensor_win::MotwZoneInfo;

    struct Gate {
        entered: AtomicBool,
        released: Mutex<bool>,
        cvar: Condvar,
    }

    impl Gate {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                entered: AtomicBool::new(false),
                released: Mutex::new(false),
                cvar: Condvar::new(),
            })
        }

        fn wait_gate(&self) {
            self.entered.store(true, Ordering::Release);
            let mut guard = self.released.lock().unwrap_or_else(|e| e.into_inner());
            while !*guard {
                guard = self.cvar.wait(guard).unwrap_or_else(|e| e.into_inner());
            }
        }

        fn release(&self) {
            let mut guard = self.released.lock().unwrap_or_else(|e| e.into_inner());
            *guard = true;
            self.cvar.notify_all();
        }

        fn is_entered(&self) -> bool {
            self.entered.load(Ordering::Acquire)
        }
    }

    struct ReleaseGatesOnDrop(Vec<Arc<Gate>>);
    impl Drop for ReleaseGatesOnDrop {
        fn drop(&mut self) {
            for gate in &self.0 {
                gate.release();
            }
        }
    }

    struct OnceGatedMotwInspector {
        target_exe_lower: String,
        gate: Arc<Gate>,
        calls: AtomicUsize,
    }

    impl MotwInspector for OnceGatedMotwInspector {
        fn read_zone_identifier(&self, path: &Path) -> Option<MotwZoneInfo> {
            if path.to_string_lossy().to_ascii_lowercase() == self.target_exe_lower
                && self.calls.fetch_add(1, Ordering::AcqRel) == 0
            {
                self.gate.wait_gate();
            }
            None
        }
    }

    struct SweepWfpDefense {
        next_handle: AtomicU64,
        target_exe_lower: String,
        target_add_calls: AtomicUsize,
        first_add_gate: Arc<Gate>,
        fail_removes: AtomicBool,
        active_handles: Mutex<HashSet<u64>>,
        remove_failures: AtomicUsize,
        remove_successes: AtomicUsize,
    }

    impl SweepWfpDefense {
        fn new(target_exe: &str, first_add_gate: Arc<Gate>) -> Self {
            Self {
                next_handle: AtomicU64::new(13_000),
                target_exe_lower: target_exe.to_ascii_lowercase(),
                target_add_calls: AtomicUsize::new(0),
                first_add_gate,
                fail_removes: AtomicBool::new(false),
                active_handles: Mutex::new(HashSet::new()),
                remove_failures: AtomicUsize::new(0),
                remove_successes: AtomicUsize::new(0),
            }
        }

        fn active_handles(&self) -> HashSet<u64> {
            self.active_handles
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
    }

    impl ActiveDefenseController for SweepWfpDefense {
        fn suspend_process(&self, _: &ProcessIdentity, _: bool) -> Result<(), String> {
            Ok(())
        }
        fn resume_process(&self, _: &ProcessIdentity) -> Result<(), String> {
            Ok(())
        }
        fn terminate_process(&self, _: &ProcessIdentity, _: bool) -> Result<(), String> {
            Ok(())
        }

        fn add_wfp_app_rule(
            &self,
            exe_path: &Path,
            _remote_ip: Option<IpAddr>,
            allow: bool,
        ) -> Result<u64, String> {
            let lower = exe_path.to_string_lossy().to_ascii_lowercase();
            let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
            self.active_handles
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(handle);
            if !allow
                && lower == self.target_exe_lower
                && self.target_add_calls.fetch_add(1, Ordering::AcqRel) == 0
            {
                self.first_add_gate.wait_gate();
            }
            Ok(handle)
        }

        fn remove_wfp_rule(&self, filter_id: u64) -> Result<(), String> {
            if self.fail_removes.load(Ordering::Acquire) {
                self.remove_failures.fetch_add(1, Ordering::Relaxed);
                return Err(format!("transient BFE busy removing {filter_id}"));
            }
            self.active_handles
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&filter_id);
            self.remove_successes.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    let sweep_exe = r"C:\Users\Alice\Downloads\periodic_sweep_race.exe";
    let active_sibling_exe = r"C:\Users\Alice\Downloads\active_sibling_keep.exe";
    let motw_gate = Gate::new();
    let seed_wfp_gate = Gate::new();
    let _release_all = ReleaseGatesOnDrop(vec![Arc::clone(&motw_gate), Arc::clone(&seed_wfp_gate)]);

    let defense = Arc::new(SweepWfpDefense::new(sweep_exe, Arc::clone(&seed_wfp_gate)));
    let motw_inspector = Arc::new(OnceGatedMotwInspector {
        target_exe_lower: sweep_exe.to_ascii_lowercase(),
        gate: Arc::clone(&motw_gate),
        calls: AtomicUsize::new(0),
    });

    let store = LedrStore::open_in_memory().expect("in-memory store");
    // alert_timeout_ms = 200 -> expiry_ticker runs every 50 ms.
    let engine = DaemonEngine::start_with_motw_inspector(
        store,
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::Enforce,
            alert_timeout_ms: 200,
            motw_sync_wait_budget_ms: 5_000,
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(StubNotifier),
        Arc::new(FixedShaInspector("9".repeat(64))),
        Arc::new(MapLiveProcessInspector::new([])),
        motw_inspector,
    );

    let sender = engine.sender();
    let now_ms = current_unix_ms();

    // Start a separate Downloads process that stays alive across all periodic sweeps.
    let sibling_pid = 8820u32;
    let sibling_create = 116_444_736_000_000_000u64 + ((now_ms - 2_000) as u64) * 10_000;
    let sibling_ident = ProcessIdentity::new(sibling_pid, sibling_create);
    let hp_before_sibling = engine.high_priority_processed.load(Ordering::Relaxed);
    sender
        .send(SensorEvent::ProcessStart {
            identity: sibling_ident,
            parent_pid: 4,
            exe_path: active_sibling_exe.to_string(),
            command_line: "active_sibling_keep.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send ProcessStart for active_sibling_exe");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while engine.high_priority_processed.load(Ordering::Relaxed) < hp_before_sibling + 1 {
        assert!(tokio::time::Instant::now() < deadline, "sibling start done");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        try_has_active_wfp_filter(
            &engine,
            active_sibling_exe,
            None,
            false,
            Duration::from_secs(2)
        )
        .await
        .expect("firewall lock available for sibling check"),
        "active_sibling_exe must have a Preemptive block"
    );

    // Trigger the seed_processes vs ETW ProcessStart/ProcessStop race for `sweep_exe`.
    let pid1 = 8821u32;
    let create1_100ns = 116_444_736_000_000_000u64 + ((now_ms - 1_000) as u64) * 10_000;
    let ident1 = ProcessIdentity::new(pid1, create1_100ns);
    sender
        .send(SensorEvent::ProcessStart {
            identity: ident1,
            parent_pid: 4,
            exe_path: sweep_exe.to_string(),
            command_line: "periodic_sweep_race.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send ProcessStart for sweep_exe");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !motw_gate.is_entered() {
        assert!(tokio::time::Instant::now() < deadline, "MOTW gate entered");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let engine_for_seed = Arc::clone(&engine);
    let seed_handle = std::thread::spawn(move || {
        engine_for_seed.seed_processes(vec![SensorEvent::ProcessStart {
            identity: ProcessIdentity::new(pid1, 0),
            parent_pid: 4,
            exe_path: sweep_exe.to_string(),
            command_line: "periodic_sweep_race.exe".to_string(),
            user_sid: None,
        }])
    });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !seed_wfp_gate.is_entered() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "seed WFP gate entered"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        !try_has_active_wfp_filter(&engine, sweep_exe, None, false, Duration::from_secs(2))
            .await
            .expect("firewall lock must not be held across in-flight add_wfp_app_rule"),
        "uncommitted seed handle must not yet be registered in WfpRuleManager"
    );

    let hp_before_start1 = engine.high_priority_processed.load(Ordering::Relaxed);
    motw_gate.release();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while engine.high_priority_processed.load(Ordering::Relaxed) < hp_before_start1 + 1
        || !try_has_active_wfp_filter(&engine, sweep_exe, None, false, Duration::from_secs(2))
            .await
            .expect("firewall lock must remain unblocked while seed_processes is paused")
    {
        assert!(tokio::time::Instant::now() < deadline, "ETW start done");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let hp_before_stop1 = engine.high_priority_processed.load(Ordering::Relaxed);
    sender
        .send(SensorEvent::ProcessStop {
            pid: pid1,
            exit_time_100ns: create1_100ns + 500_000,
            exit_code: 0,
        })
        .await
        .expect("send ProcessStop for sweep_exe");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while engine.high_priority_processed.load(Ordering::Relaxed) < hp_before_stop1 + 1 {
        assert!(tokio::time::Instant::now() < deadline, "ETW stop done");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        !try_has_active_wfp_filter(&engine, sweep_exe, None, false, Duration::from_secs(2))
            .await
            .expect("firewall lock unblocked after ProcessStop")
    );

    // Fail removal when seed_processes resumes so the obsolete handle is retained as Preemptive.
    defense.fail_removes.store(true, Ordering::Release);
    seed_wfp_gate.release();
    let seeded = tokio::task::spawn_blocking(move || seed_handle.join())
        .await
        .expect("join spawn_blocking")
        .expect("seed_processes thread panicked")
        .expect("seed_processes returned error");
    assert_eq!(seeded, 1);

    // Wait for at least one periodic `expiry_ticker` retry while BFE is still failing.
    let failures_after_seed = defense.remove_failures.load(Ordering::Relaxed);
    assert!(failures_after_seed >= 1);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while defense.remove_failures.load(Ordering::Relaxed) <= failures_after_seed {
        assert!(
            tokio::time::Instant::now() < deadline,
            "periodic expiry_ticker sweep must retry removing retained unused Preemptive block"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        try_has_active_wfp_filter(&engine, sweep_exe, None, false, Duration::from_secs(2))
            .await
            .expect("firewall lock available during failed sweeps"),
        "retained filter must remain tracked while BFE removal continues to fail"
    );

    // Recover BFE WITHOUT relaunching `sweep_exe` or adding any `NetworkAllow` rule.
    // The periodic `expiry_ticker` sweep must remove `sweep_exe` automatically while keeping
    // `active_sibling_exe`'s Preemptive block intact.
    defense.fail_removes.store(false, Ordering::Release);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while try_has_active_wfp_filter(&engine, sweep_exe, None, false, Duration::from_secs(2))
        .await
        .expect("firewall lock available during recovery sweeps")
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "periodic sweep must self-heal retained unused Preemptive block once BFE recovers"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        try_has_active_wfp_filter(
            &engine,
            active_sibling_exe,
            None,
            false,
            Duration::from_secs(2)
        )
        .await
        .expect("firewall lock available after recovery sweep"),
        "periodic sweep must NOT remove Preemptive block of still-running sibling executable"
    );
    assert_eq!(
        defense.active_handles().len(),
        1,
        "only active_sibling_exe's BFE handle must remain"
    );
    assert_eq!(defense.remove_successes.load(Ordering::Relaxed), 2);

    // Stop active_sibling_exe and confirm full BFE cleanup.
    let hp_before_sibling_stop = engine.high_priority_processed.load(Ordering::Relaxed);
    sender
        .send(SensorEvent::ProcessStop {
            pid: sibling_pid,
            exit_time_100ns: sibling_create + 500_000,
            exit_code: 0,
        })
        .await
        .expect("send ProcessStop for active_sibling_exe");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while engine.high_priority_processed.load(Ordering::Relaxed) < hp_before_sibling_stop + 1 {
        assert!(tokio::time::Instant::now() < deadline, "sibling stop done");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        !try_has_active_wfp_filter(
            &engine,
            active_sibling_exe,
            None,
            false,
            Duration::from_secs(2)
        )
        .await
        .expect("firewall lock available after sibling stop")
    );
    assert!(defense.active_handles().is_empty());

    engine.shutdown_and_flush().await.expect("shutdown engine");
}

/// Negative verification for [`try_has_active_wfp_filter`] (`PRRT_kwDOVyjVyM66kD-5`): when
/// another thread holds `engine.firewall.lock()`, the bounded probe returns `Err(...)` cleanly on
/// timeout instead of deadlocking the test task.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn try_has_active_wfp_filter_times_out_when_firewall_lock_is_held() {
    use std::sync::atomic::AtomicBool;
    use std::sync::Condvar;
    use std::time::Duration;

    let store = LedrStore::open_in_memory().expect("in-memory store");
    let engine = DaemonEngine::start_with_all_dependencies(
        store,
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig::default(),
        Arc::new(RecordingDefense::new()),
        Arc::new(StubNotifier),
        Arc::new(FixedShaInspector("a".repeat(64))),
        Arc::new(MapLiveProcessInspector::new([])),
    );

    let locked = Arc::new(AtomicBool::new(false));
    let timed_out_by_holder = Arc::new(AtomicBool::new(false));
    let release_pair = Arc::new((Mutex::new(false), Condvar::new()));
    let locked_bg = Arc::clone(&locked);
    let timed_out_bg = Arc::clone(&timed_out_by_holder);
    let release_bg = Arc::clone(&release_pair);
    let engine_bg = Arc::clone(&engine);

    struct ReleaseOnDrop(Arc<(Mutex<bool>, Condvar)>);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            let mut released = self.0 .0.lock().unwrap_or_else(|e| e.into_inner());
            *released = true;
            self.0 .1.notify_all();
        }
    }
    let _release_guard = ReleaseOnDrop(Arc::clone(&release_pair));

    // Independent safety deadline (`PRRT_kwDOVyjVyM66kfFO`): even if `try_has_active_wfp_filter`
    // ever regressed to an unbounded blocking `lock()`, `holder` self-releases after 5 seconds so
    // the probe unblocks and fails the `expect_err` assertion instead of deadlocking the test.
    let holder = std::thread::spawn(move || {
        let _fw_guard = engine_bg.firewall.lock().unwrap_or_else(|e| e.into_inner());
        locked_bg.store(true, Ordering::Release);
        let safety_deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut released = release_bg.0.lock().unwrap_or_else(|e| e.into_inner());
        while !*released {
            let Some(remaining) =
                safety_deadline.checked_duration_since(std::time::Instant::now())
            else {
                timed_out_bg.store(true, Ordering::Release);
                break;
            };
            let (guard, wait_res) = release_bg
                .1
                .wait_timeout(released, remaining)
                .unwrap_or_else(|e| e.into_inner());
            released = guard;
            if wait_res.timed_out() && !*released {
                timed_out_bg.store(true, Ordering::Release);
                break;
            }
        }
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while !locked.load(Ordering::Acquire) {
        assert!(tokio::time::Instant::now() < deadline, "holder acquired lock");
        tokio::time::sleep(Duration::from_millis(2)).await;
    }

    let err = try_has_active_wfp_filter(
        &engine,
        r"C:\Users\Alice\Downloads\held_lock.exe",
        None,
        false,
        Duration::from_millis(30),
    )
    .await
    .expect_err("try_has_active_wfp_filter must time out cleanly when firewall lock is held");
    assert!(
        err.contains("timed out"),
        "expected timeout diagnostic, got: {err}"
    );
    assert!(
        !timed_out_by_holder.load(Ordering::Acquire),
        "probe must time out on its own bounded deadline well before holder's safety deadline"
    );

    drop(_release_guard);
    tokio::task::spawn_blocking(move || holder.join())
        .await
        .expect("join spawn_blocking")
        .expect("holder thread exited cleanly");

    assert!(
        !try_has_active_wfp_filter(
            &engine,
            r"C:\Users\Alice\Downloads\held_lock.exe",
            None,
            false,
            Duration::from_secs(1),
        )
        .await
        .expect("firewall lock must succeed after holder releases it")
    );

    engine.shutdown_and_flush().await.expect("shutdown engine");
}

/// `DAEMON-P4-CMD-10`: Verifies two periodic-sweep invariants end-to-end against the real
/// `pipeline.rs` event loop and `ActiveProcessTable`:
/// 1. (`PRRT_kwDOVyjVyM66kWF3`) Sustained Tier 3 steady telemetry backlog must NOT starve the
///    periodic `sweep_unused_preemptive_wfp_blocks` retry: a retained pending-removal `Preemptive`
///    block is cleaned up automatically while the telemetry queue remains continuously backlogged.
/// 2. (`PRRT_kwDOVyjVyM66kWHQ`) A still-running unapproved executable whose entry was evicted from
///    `ActiveProcessTable` under capacity pressure (`evict_if_over_capacity`) must KEEP its live
///    `Preemptive` WFP block across those exact same periodic sweeps.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_p4_cmd_10_sweep_runs_under_telemetry_backlog_and_preserves_evicted_active_block() {
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::time::Duration;

    use crate::firewall::WfpRuleManager;
    use crate::process_table::ActiveProcessTable;

    struct ToggleFailWfpDefense {
        next_handle: AtomicU64,
        fail_removes: AtomicBool,
        active_handles: Mutex<HashSet<u64>>,
        remove_failures: AtomicUsize,
        remove_successes: AtomicUsize,
        telemetry_sender: Mutex<Option<crate::channel::TwoLaneSender>>,
        telemetry_depth_at_remove_success: AtomicUsize,
    }

    impl ToggleFailWfpDefense {
        fn new() -> Self {
            Self {
                next_handle: AtomicU64::new(15_000),
                fail_removes: AtomicBool::new(false),
                active_handles: Mutex::new(HashSet::new()),
                remove_failures: AtomicUsize::new(0),
                remove_successes: AtomicUsize::new(0),
                telemetry_sender: Mutex::new(None),
                telemetry_depth_at_remove_success: AtomicUsize::new(0),
            }
        }

        fn active_handles(&self) -> HashSet<u64> {
            self.active_handles
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
    }

    impl ActiveDefenseController for ToggleFailWfpDefense {
        fn suspend_process(&self, _: &ProcessIdentity, _: bool) -> Result<(), String> {
            Ok(())
        }
        fn resume_process(&self, _: &ProcessIdentity) -> Result<(), String> {
            Ok(())
        }
        fn terminate_process(&self, _: &ProcessIdentity, _: bool) -> Result<(), String> {
            Ok(())
        }
        fn add_wfp_app_rule(
            &self,
            _exe_path: &Path,
            _remote_ip: Option<IpAddr>,
            _allow: bool,
        ) -> Result<u64, String> {
            let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
            self.active_handles
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(handle);
            Ok(handle)
        }
        fn remove_wfp_rule(&self, filter_id: u64) -> Result<(), String> {
            if self.fail_removes.load(Ordering::Acquire) {
                self.remove_failures.fetch_add(1, Ordering::Relaxed);
                return Err(format!("transient BFE error removing {filter_id}"));
            }
            self.active_handles
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&filter_id);
            if let Some(tx) = self
                .telemetry_sender
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
            {
                self.telemetry_depth_at_remove_success
                    .store(tx.telemetry_depth(), Ordering::Release);
            }
            self.remove_successes.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    let defense = Arc::new(ToggleFailWfpDefense::new());
    let store = LedrStore::open_in_memory().expect("in-memory store");
    // alert_timeout_ms = 200 -> expiry_interval = 50 ms.
    let engine = DaemonEngine::start_with_all_dependencies(
        store,
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::Enforce,
            alert_timeout_ms: 200,
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(StubNotifier),
        Arc::new(FixedShaInspector("7".repeat(64))),
        Arc::new(MapLiveProcessInspector::new([])),
    );

    // Shrink ActiveProcessTable capacity to 2 so 3 active processes deterministically trigger real
    // active-entry eviction (`evict_if_over_capacity`, `process_table.rs:942-954`).
    {
        let mut table = engine
            .process_table
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *table = ActiveProcessTable::new(2);
    }

    let sender = engine.sender();
    *defense
        .telemetry_sender
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some(sender.clone());
    let now_ms = current_unix_ms();
    let base_100ns = 116_444_736_000_000_000u64 + ((now_ms - 5_000) as u64) * 10_000;

    let evicted_live_exe = r"C:\Users\Alice\Downloads\evicted_still_running.exe";
    let backlog_sweep_exe = r"C:\Users\Alice\Downloads\backlog_retry_cleanup.exe";
    let pad1_exe = r"C:\Program Files\BenignPad\pad1.exe";
    let pad2_exe = r"C:\Program Files\BenignPad\pad2.exe";

    // 1. Start `evicted_live_exe` (receives live Preemptive WFP block) and stay running.
    let hp_before = engine.high_priority_processed.load(Ordering::Relaxed);
    sender
        .send(SensorEvent::ProcessStart {
            identity: ProcessIdentity::new(9101, base_100ns),
            parent_pid: 4,
            exe_path: evicted_live_exe.to_string(),
            command_line: "evicted_still_running.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send ProcessStart evicted_live_exe");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while engine.high_priority_processed.load(Ordering::Relaxed) < hp_before + 1 {
        assert!(tokio::time::Instant::now() < deadline, "evicted_live start");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        try_has_active_wfp_filter(&engine, evicted_live_exe, None, false, Duration::from_secs(2))
            .await
            .expect("firewall lock available"),
        "evicted_live_exe must have live Preemptive block"
    );

    // 2. Start `backlog_sweep_exe`, then stop it while BFE fails removal so it enters
    //    `pending_preemptive_removals`.
    let hp_before = engine.high_priority_processed.load(Ordering::Relaxed);
    sender
        .send(SensorEvent::ProcessStart {
            identity: ProcessIdentity::new(9102, base_100ns + 10_000),
            parent_pid: 4,
            exe_path: backlog_sweep_exe.to_string(),
            command_line: "backlog_retry_cleanup.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send ProcessStart backlog_sweep_exe");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while engine.high_priority_processed.load(Ordering::Relaxed) < hp_before + 1 {
        assert!(tokio::time::Instant::now() < deadline, "backlog_sweep start");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        try_has_active_wfp_filter(&engine, backlog_sweep_exe, None, false, Duration::from_secs(2))
            .await
            .expect("firewall lock available")
    );

    defense.fail_removes.store(true, Ordering::Release);
    let hp_before = engine.high_priority_processed.load(Ordering::Relaxed);
    sender
        .send(SensorEvent::ProcessStop {
            pid: 9102,
            exit_time_100ns: base_100ns + 20_000,
            exit_code: 0,
        })
        .await
        .expect("send ProcessStop backlog_sweep_exe");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while engine.high_priority_processed.load(Ordering::Relaxed) < hp_before + 1 {
        assert!(tokio::time::Instant::now() < deadline, "backlog_sweep stop");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        defense.remove_failures.load(Ordering::Relaxed) >= 1,
        "ProcessStop removal failure must be recorded"
    );

    // 3. Start two active benign processes so `ActiveProcessTable` (cap=2) evicts the exited
    //    `backlog_sweep_exe` AND the still-running `evicted_live_exe`.
    let hp_before = engine.high_priority_processed.load(Ordering::Relaxed);
    sender
        .send(SensorEvent::ProcessStart {
            identity: ProcessIdentity::new(9103, base_100ns + 30_000),
            parent_pid: 4,
            exe_path: pad1_exe.to_string(),
            command_line: "pad1.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send ProcessStart pad1");
    sender
        .send(SensorEvent::ProcessStart {
            identity: ProcessIdentity::new(9104, base_100ns + 40_000),
            parent_pid: 4,
            exe_path: pad2_exe.to_string(),
            command_line: "pad2.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send ProcessStart pad2");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while engine.high_priority_processed.load(Ordering::Relaxed) < hp_before + 2 {
        assert!(tokio::time::Instant::now() < deadline, "pad starts done");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    {
        let table = engine
            .process_table
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let evicted_live_id = ProcessIdentity::new(9101, base_100ns).instance_id();
        assert!(
            table.get_by_instance_id(&evicted_live_id).is_none(),
            "ActiveProcessTable capacity pressure must have evicted still-running evicted_live_exe from primary entries"
        );
        assert!(
            table.has_active_exe_key(&WfpRuleManager::exe_key(evicted_live_exe)),
            "ActiveProcessTable must continue distinguishing evicted live process from exited processes"
        );
    }

    // 4. Continuously flood Tier 3 steady telemetry so the telemetry queue NEVER drains to empty
    //    while BFE recovers; verify Tier 2c still sweeps `backlog_sweep_exe` without waiting for
    //    telemetry to go idle, while `evicted_live_exe`'s live Preemptive block stays intact.
    let stop_flood = Arc::new(AtomicBool::new(false));
    struct StopFloodOnDrop(Arc<AtomicBool>);
    impl Drop for StopFloodOnDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    let _flood_guard = StopFloodOnDrop(Arc::clone(&stop_flood));

    let flood_sender = sender.clone();
    let flood_flag = Arc::clone(&stop_flood);
    let telemetry_at_flood_start = engine.telemetry_processed.load(Ordering::Acquire);
    // Pre-fill telemetry ring before starting background flooder so Tier 3 is already non-empty.
    for i in 0..6_000u16 {
        let _ = flood_sender.send_telemetry(SensorEvent::NetworkConnect {
            pid: 99_999,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            dst_port: 10_000 + i,
            domain_hint: None,
            timestamp_ms: now_ms,
        });
    }
    let flood_thread = std::thread::spawn(move || {
        let mut seq = 0u16;
        while !flood_flag.load(Ordering::Acquire) {
            if flood_sender.telemetry_depth() < 6_000 {
                for _ in 0..256 {
                    seq = seq.wrapping_add(1);
                    if flood_sender
                        .send_telemetry(SensorEvent::NetworkConnect {
                            pid: 99_999,
                            protocol: 6,
                            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
                            dst_port: 20_000u16.wrapping_add(seq),
                            domain_hint: None,
                            timestamp_ms: now_ms,
                        })
                        .is_err()
                    {
                        return;
                    }
                }
            } else {
                std::thread::yield_now();
            }
        }
    });

    // Wait until the pipeline worker has woken up and is actively consuming Tier 3 telemetry
    // before enabling BFE recovery so we snapshot the idle `select!` sweep baseline cleanly.
    let wake_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while engine.telemetry_processed.load(Ordering::Acquire) <= telemetry_at_flood_start {
        assert!(
            tokio::time::Instant::now() < wake_deadline,
            "worker must start consuming flooded telemetry"
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }

    // Recover BFE under active telemetry flood.
    let telemetry_before_recovery = engine.telemetry_processed.load(Ordering::Acquire);
    let tier2c_sweeps_before = engine.tier2c_periodic_sweeps.load(Ordering::Acquire);
    let select_idle_sweeps_before = engine.select_idle_periodic_sweeps.load(Ordering::Acquire);
    defense.fail_removes.store(false, Ordering::Release);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while try_has_active_wfp_filter(&engine, backlog_sweep_exe, None, false, Duration::from_secs(2))
        .await
        .expect("firewall lock available during telemetry backlog")
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "periodic sweep must remove pending-removal Preemptive block even under continuous Tier 3 telemetry backlog"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Directly observe which pipeline branch executed the removal (`PRRT_kwDOVyjVyM66kfEX`):
    // proves removal happened strictly inside Tier 2c (pre-telemetry overdue branch) rather than
    // falling through into the idle `tokio::select!` expiry arm.
    let telemetry_at_sweep = engine.telemetry_processed.load(Ordering::Acquire);
    assert!(
        telemetry_at_sweep > telemetry_before_recovery,
        "telemetry lane must have been actively processing events during the sweep"
    );
    assert_eq!(
        engine.tier2c_periodic_sweep_removals.load(Ordering::Acquire),
        1,
        "removal of backlog_sweep_exe must be executed by the Tier 2c pre-telemetry branch"
    );
    assert_eq!(
        engine
            .select_idle_periodic_sweep_removals
            .load(Ordering::Acquire),
        0,
        "idle select! expiry branch must NOT have executed the removal"
    );
    assert!(
        engine.tier2c_periodic_sweeps.load(Ordering::Acquire) > tier2c_sweeps_before,
        "Tier 2c periodic sweep counter must have advanced during telemetry backlog"
    );
    assert_eq!(
        engine.select_idle_periodic_sweeps.load(Ordering::Acquire),
        select_idle_sweeps_before,
        "pipeline must not have fallen into the idle select! expiry branch while telemetry was flooded"
    );
    assert!(
        defense
            .telemetry_depth_at_remove_success
            .load(Ordering::Acquire)
            > 0,
        "telemetry queue must still be non-empty when Tier 2c periodic sweep removes the retained block"
    );

    // Wait one more expiry_interval under the same conditions to prove repeated sweeps NEVER
    // remove `evicted_live_exe`'s live Preemptive WFP block.
    tokio::time::sleep(Duration::from_millis(120)).await;

    stop_flood.store(true, Ordering::Release);
    tokio::task::spawn_blocking(move || flood_thread.join())
        .await
        .expect("join flood spawn_blocking")
        .expect("flood thread exited cleanly");

    assert!(
        try_has_active_wfp_filter(&engine, evicted_live_exe, None, false, Duration::from_secs(2))
            .await
            .expect("firewall lock available after sweeps"),
        "still-running evicted_live_exe must keep its Preemptive WFP block despite ProcessTable eviction"
    );
    assert_eq!(
        defense.active_handles().len(),
        1,
        "only evicted_live_exe's OS BFE handle must remain active"
    );
    assert_eq!(
        defense.remove_successes.load(Ordering::Relaxed),
        1,
        "only backlog_sweep_exe's pending-removal handle must have been removed"
    );

    engine.shutdown_and_flush().await.expect("shutdown engine");
}

/// Regression test `WFP-DEFERRED-02` (`PRRT_kwDOVyjVyM66kfDX`):
/// verifies that when `ProcessStop` arrives BEFORE a sibling `LAYER_3_NETWORK` alert is
/// auto-resolved by `resolve_sibling_alerts_as_terminated`, releasing the last bound alert
/// immediately removes the deferred `Preemptive` WFP block (or queues it into
/// `pending_preemptive_removals` for periodic sweep retry when BFE fails removal), while NEVER
/// stripping a live sibling's `Preemptive` block based solely on `ActiveProcessTable` eviction.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sibling_alert_auto_resolve_after_process_stop_removes_deferred_preemptive_block_and_respects_live_eviction()
{
    use std::collections::HashSet;
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

    use crate::firewall::{WfpFilterOrigin, WfpRuleManager};
    use crate::process_table::ActiveProcessTable;

    struct ToggleRemoveDefense {
        next_handle: AtomicU64,
        fail_removes: AtomicBool,
        active_handles: Mutex<HashSet<u64>>,
    }

    impl ToggleRemoveDefense {
        fn new() -> Self {
            Self {
                next_handle: AtomicU64::new(9300),
                fail_removes: AtomicBool::new(false),
                active_handles: Mutex::new(HashSet::new()),
            }
        }
        fn active_handles(&self) -> HashSet<u64> {
            self.active_handles
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
    }

    impl ActiveDefenseController for ToggleRemoveDefense {
        fn suspend_process(&self, _: &ProcessIdentity, _: bool) -> Result<(), String> {
            Ok(())
        }
        fn resume_process(&self, _: &ProcessIdentity) -> Result<(), String> {
            Ok(())
        }
        fn terminate_process(&self, _: &ProcessIdentity, _: bool) -> Result<(), String> {
            Ok(())
        }
        fn add_wfp_app_rule(
            &self,
            _exe_path: &Path,
            _remote_ip: Option<IpAddr>,
            _allow: bool,
        ) -> Result<u64, String> {
            let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
            self.active_handles
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(handle);
            Ok(handle)
        }
        fn remove_wfp_rule(&self, filter_id: u64) -> Result<(), String> {
            if self.fail_removes.load(Ordering::Acquire) {
                return Err(format!("transient BFE error removing {filter_id}"));
            }
            self.active_handles
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&filter_id);
            Ok(())
        }
    }

    let defense = Arc::new(ToggleRemoveDefense::new());
    let store = LedrStore::open_in_memory().expect("in-memory store");
    // alert_timeout_ms = 200 -> expiry_interval = 50 ms for fast periodic sweep verification.
    let engine = DaemonEngine::start_with_all_dependencies(
        store,
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::Enforce,
            alert_timeout_ms: 200,
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(StubNotifier),
        Arc::new(FixedShaInspector("b".repeat(64))),
        Arc::new(MapLiveProcessInspector::new([])),
    );
    let sender = engine.sender();
    let now_ms = current_unix_ms();
    let base_100ns = 116_444_736_000_000_000u64 + ((now_ms - 5_000) as u64) * 10_000;

    let wait_hp = |target: u64| {
        let eng = Arc::clone(&engine);
        async move {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            while eng.high_priority_processed.load(Ordering::Relaxed) < target {
                assert!(tokio::time::Instant::now() < deadline, "wait_hp({target})");
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    };

    // --- Sub-case A: ProcessStop arrives BEFORE sibling alert auto-resolve -> immediate removal ---
    let exe_a = r"C:\Users\Alice\Downloads\sibling_stop_first_immediate.exe";
    let id_a = ProcessIdentity::new(9310, base_100ns);
    let inst_a = id_a.instance_id();

    let hp = engine.high_priority_processed.load(Ordering::Relaxed);
    sender
        .send(SensorEvent::ProcessStart {
            identity: id_a,
            parent_pid: 4,
            exe_path: exe_a.to_string(),
            command_line: "sibling_stop_first_immediate.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send start A");
    wait_hp(hp + 1).await;
    assert!(
        try_has_active_wfp_filter(&engine, exe_a, None, false, Duration::from_secs(2))
            .await
            .expect("fw lock")
    );

    let mk_alert = |alert_id: &str,
                    source_layer: &str,
                    rule_id: &str,
                    title: &str,
                    proc_inst: &str,
                    exe: &str| AlertRecord {
        alert_id: alert_id.to_string(),
        timestamp_ms: now_ms,
        source_layer: source_layer.to_string(),
        severity: AlertSeverity::High,
        rule_id: rule_id.to_string(),
        title: title.to_string(),
        process_instance_id: Some(proc_inst.to_string()),
        process_suspended: false,
        status: AlertStatus::Pending,
        context_json: serde_json::json!({ "exe_path": exe }).to_string(),
        resolved_at_ms: None,
    };

    // Record non-network Alert A1 (Sigma/Rule) and sibling network Alert A2 bound to Preemptive block.
    let alert_a1 = mk_alert(
        "ALT-SIB-A1",
        "LAYER_1_PROCESS",
        "SIGMA-TEST-A1",
        "Test rule alert A1",
        &inst_a,
        exe_a,
    );
    let alert_a2 = mk_alert(
        "ALT-SIB-A2",
        "LAYER_3_NETWORK",
        "WFP-PREEMPT-A2",
        "Test network alert A2",
        &inst_a,
        exe_a,
    );
    engine.store.record_alert(&alert_a1).expect("record A1");
    engine.store.record_alert(&alert_a2).expect("record A2");
    {
        let mut fw = engine.firewall.lock().unwrap_or_else(|e| e.into_inner());
        assert!(fw.bind_alert_to_app_block(&alert_a2.alert_id, exe_a));
    }

    // ProcessStop arrives FIRST while Alert A2 is still unresolved & bound -> removal deferred.
    let hp = engine.high_priority_processed.load(Ordering::Relaxed);
    sender
        .send(SensorEvent::ProcessStop {
            pid: id_a.pid,
            exit_time_100ns: base_100ns + 10_000,
            exit_code: 0,
        })
        .await
        .expect("send stop A");
    wait_hp(hp + 1).await;
    {
        let fw = engine.firewall.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            fw.has_active_filter(exe_a, None, false),
            "bound alert A2 must keep Preemptive block active across ProcessStop"
        );
        assert!(
            fw.has_deferred_preemptive_removal(exe_a),
            "ProcessStop must record deferred removal while bound alert A2 blocks deletion"
        );
        assert!(
            !fw.has_pending_preemptive_removal(exe_a),
            "deferred removal must not populate pending_preemptive_removals while alert is open"
        );
    }

    // User resolves non-network Alert A1 via TerminateAndBlock { add_block_rule: false }.
    // `resolve_sibling_alerts_as_terminated` auto-resolves A2 and immediately removes the deferred block.
    engine
        .resolve_alert(
            &alert_a1.alert_id,
            ledr_proto::AlertDecision::TerminateAndBlock {
                add_block_rule: false,
            },
        )
        .expect("resolve A1");
    assert_eq!(
        engine
            .store
            .get_alert(&alert_a2.alert_id)
            .expect("get A2")
            .expect("A2 exists")
            .status,
        AlertStatus::TerminatedBlocked
    );
    assert!(
        !try_has_active_wfp_filter(&engine, exe_a, None, false, Duration::from_secs(2))
            .await
            .expect("fw lock"),
        "deferred Preemptive block must be removed immediately when sibling network alert A2 auto-resolves"
    );
    assert!(defense.active_handles().is_empty());

    // --- Sub-case B: BFE fails during sibling auto-resolve -> queues into periodic sweep retry ---
    let exe_b = r"C:\Users\Alice\Downloads\sibling_stop_first_bfe_retry.exe";
    let id_b = ProcessIdentity::new(9311, base_100ns + 20_000);
    let inst_b = id_b.instance_id();

    let hp = engine.high_priority_processed.load(Ordering::Relaxed);
    sender
        .send(SensorEvent::ProcessStart {
            identity: id_b,
            parent_pid: 4,
            exe_path: exe_b.to_string(),
            command_line: "sibling_stop_first_bfe_retry.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send start B");
    wait_hp(hp + 1).await;

    let alert_b1 = mk_alert(
        "ALT-SIB-B1",
        "LAYER_1_PROCESS",
        "SIGMA-TEST-B1",
        "Test rule alert B1",
        &inst_b,
        exe_b,
    );
    let alert_b2 = mk_alert(
        "ALT-SIB-B2",
        "LAYER_3_NETWORK",
        "WFP-PREEMPT-B2",
        "Test network alert B2",
        &inst_b,
        exe_b,
    );
    engine.store.record_alert(&alert_b1).expect("record B1");
    engine.store.record_alert(&alert_b2).expect("record B2");
    {
        let mut fw = engine.firewall.lock().unwrap_or_else(|e| e.into_inner());
        assert!(fw.bind_alert_to_app_block(&alert_b2.alert_id, exe_b));
    }

    let hp = engine.high_priority_processed.load(Ordering::Relaxed);
    sender
        .send(SensorEvent::ProcessStop {
            pid: id_b.pid,
            exit_time_100ns: base_100ns + 30_000,
            exit_code: 0,
        })
        .await
        .expect("send stop B");
    wait_hp(hp + 1).await;

    // Inject transient BFE failure before resolving B1 -> sibling auto-resolve must queue into
    // `pending_preemptive_removals`, and periodic sweep must clean it up once BFE recovers.
    defense.fail_removes.store(true, Ordering::Release);
    engine
        .resolve_alert(
            &alert_b1.alert_id,
            ledr_proto::AlertDecision::TerminateAndBlock {
                add_block_rule: false,
            },
        )
        .expect("resolve B1");
    {
        let fw = engine.firewall.lock().unwrap_or_else(|e| e.into_inner());
        assert!(fw.has_active_filter(exe_b, None, false));
        assert!(
            fw.has_pending_preemptive_removal(exe_b),
            "BFE failure when releasing deferred Preemptive block must queue handle for periodic sweep"
        );
    }

    defense.fail_removes.store(false, Ordering::Release);
    let sweep_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while try_has_active_wfp_filter(&engine, exe_b, None, false, Duration::from_secs(2))
        .await
        .expect("fw lock")
    {
        assert!(
            tokio::time::Instant::now() < sweep_deadline,
            "periodic sweep must remove exe_b's queued Preemptive block once BFE recovers"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(defense.active_handles().is_empty());

    // --- Sub-case C: Live sibling evicted from ActiveProcessTable must NOT lose its block ---
    {
        let mut table = engine
            .process_table
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *table = ActiveProcessTable::new(2);
    }
    let exe_c = r"C:\Users\Alice\Downloads\live_sibling_evicted.exe";
    let pad1_c = r"C:\Program Files\BenignPad\pad1_c.exe";
    let pad2_c = r"C:\Program Files\BenignPad\pad2_c.exe";
    let id_c1 = ProcessIdentity::new(9320, base_100ns + 40_000);
    let id_c2 = ProcessIdentity::new(9321, base_100ns + 50_000);
    let inst_c2 = id_c2.instance_id();

    let hp = engine.high_priority_processed.load(Ordering::Relaxed);
    sender
        .send(SensorEvent::ProcessStart {
            identity: id_c1,
            parent_pid: 4,
            exe_path: exe_c.to_string(),
            command_line: "live_sibling_evicted.exe --worker-1".to_string(),
            user_sid: None,
        })
        .await
        .expect("start C1");
    sender
        .send(SensorEvent::ProcessStart {
            identity: id_c2,
            parent_pid: 4,
            exe_path: exe_c.to_string(),
            command_line: "live_sibling_evicted.exe --worker-2".to_string(),
            user_sid: None,
        })
        .await
        .expect("start C2");
    wait_hp(hp + 2).await;

    let alert_c1 = mk_alert(
        "ALT-SIB-C1",
        "LAYER_1_PROCESS",
        "SIGMA-TEST-C1",
        "Test rule alert C1",
        &inst_c2,
        exe_c,
    );
    let alert_c2 = mk_alert(
        "ALT-SIB-C2",
        "LAYER_3_NETWORK",
        "WFP-PREEMPT-C2",
        "Test network alert C2",
        &inst_c2,
        exe_c,
    );
    engine.store.record_alert(&alert_c1).expect("record C1");
    engine.store.record_alert(&alert_c2).expect("record C2");
    {
        let mut fw = engine.firewall.lock().unwrap_or_else(|e| e.into_inner());
        assert!(fw.bind_alert_to_app_block(&alert_c2.alert_id, exe_c));
    }

    // C2 stops while live sibling C1 is STILL active -> ProcessStop must NOT mark deferred removal.
    let hp = engine.high_priority_processed.load(Ordering::Relaxed);
    sender
        .send(SensorEvent::ProcessStop {
            pid: id_c2.pid,
            exit_time_100ns: base_100ns + 60_000,
            exit_code: 0,
        })
        .await
        .expect("stop C2");
    wait_hp(hp + 1).await;

    // Now evict live sibling C1 from ActiveProcessTable (cap=2) using two benign processes.
    let hp = engine.high_priority_processed.load(Ordering::Relaxed);
    sender
        .send(SensorEvent::ProcessStart {
            identity: ProcessIdentity::new(9322, base_100ns + 70_000),
            parent_pid: 4,
            exe_path: pad1_c.to_string(),
            command_line: "pad1_c.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("start pad1_c");
    sender
        .send(SensorEvent::ProcessStart {
            identity: ProcessIdentity::new(9323, base_100ns + 80_000),
            parent_pid: 4,
            exe_path: pad2_c.to_string(),
            command_line: "pad2_c.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("start pad2_c");
    wait_hp(hp + 2).await;
    {
        let table = engine
            .process_table
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        assert!(
            table.get_by_instance_id(&id_c1.instance_id()).is_none(),
            "capacity pressure must have evicted still-running C1 from primary ActiveProcessTable entries"
        );
        assert!(
            table.has_active_exe_key(&WfpRuleManager::exe_key(exe_c)),
            "ActiveProcessTable must continue distinguishing evicted live C1 from exited processes"
        );
    }

    // Resolve C1 -> auto-resolves C2. Because ProcessStop never saw last-exit (C1 was active when
    // C2 exited), C1's live Preemptive block MUST stay intact despite ActiveProcessTable eviction!
    engine
        .resolve_alert(
            &alert_c1.alert_id,
            ledr_proto::AlertDecision::TerminateAndBlock {
                add_block_rule: false,
            },
        )
        .expect("resolve C1");
    {
        let fw = engine.firewall.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(
            fw.filter_origin(exe_c, None),
            Some(&WfpFilterOrigin::Preemptive),
            "evicted live sibling C1 must retain its Preemptive block after C2's sibling alert auto-resolves"
        );
        assert!(!fw.has_deferred_preemptive_removal(exe_c));
        assert!(!fw.has_pending_preemptive_removal(exe_c));
    }

    engine.shutdown_and_flush().await.expect("shutdown engine");
}

/// Regression test `WFP-ROLLBACK-02` (`PRRT_kwDOVyjVyM66kfDu`):
/// verifies end-to-end `DaemonEngine::upsert_policy_rule` rollback when promoting a
/// pending-removal `Preemptive` block to `PersistedPolicy` succeeds, while removing a conflicting
/// `DomainPolicy` Permit filter in the same policy edit fails -> rollback must restore both the
/// `Preemptive` origin AND its `pending_preemptive_removals` entry so periodic sweep cleans it up.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policy_upsert_rollback_restores_pending_preemptive_removal_for_periodic_sweep() {
    use std::collections::HashSet;
    use std::time::Duration;

    use crate::engine::PolicyRuleError;
    use crate::firewall::WfpFilterOrigin;

    struct SelectiveFailRemoveDefense {
        next_handle: AtomicU64,
        fail_handles: Mutex<HashSet<u64>>,
        active_handles: Mutex<HashSet<u64>>,
    }

    impl SelectiveFailRemoveDefense {
        fn new() -> Self {
            Self {
                next_handle: AtomicU64::new(9400),
                fail_handles: Mutex::new(HashSet::new()),
                active_handles: Mutex::new(HashSet::new()),
            }
        }
        fn set_fail_handle(&self, handle: u64, fail: bool) {
            let mut set = self.fail_handles.lock().unwrap_or_else(|e| e.into_inner());
            if fail {
                set.insert(handle);
            } else {
                set.remove(&handle);
            }
        }
    }

    impl ActiveDefenseController for SelectiveFailRemoveDefense {
        fn suspend_process(&self, _: &ProcessIdentity, _: bool) -> Result<(), String> {
            Ok(())
        }
        fn resume_process(&self, _: &ProcessIdentity) -> Result<(), String> {
            Ok(())
        }
        fn terminate_process(&self, _: &ProcessIdentity, _: bool) -> Result<(), String> {
            Ok(())
        }
        fn add_wfp_app_rule(
            &self,
            _exe_path: &Path,
            _remote_ip: Option<IpAddr>,
            _allow: bool,
        ) -> Result<u64, String> {
            let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
            self.active_handles
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(handle);
            Ok(handle)
        }
        fn remove_wfp_rule(&self, filter_id: u64) -> Result<(), String> {
            if self
                .fail_handles
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(&filter_id)
            {
                return Err(format!("injected BFE remove failure for handle {filter_id}"));
            }
            self.active_handles
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&filter_id);
            Ok(())
        }
    }

    let defense = Arc::new(SelectiveFailRemoveDefense::new());
    let store = LedrStore::open_in_memory().expect("in-memory store");
    // alert_timeout_ms = 200 -> expiry_interval = 50 ms.
    let engine = DaemonEngine::start_with_all_dependencies(
        store,
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::Enforce,
            alert_timeout_ms: 200,
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(StubNotifier),
        Arc::new(FixedShaInspector("c".repeat(64))),
        Arc::new(MapLiveProcessInspector::new([])),
    );
    let sender = engine.sender();
    let now_ms = current_unix_ms();
    let base_100ns = 116_444_736_000_000_000u64 + ((now_ms - 5_000) as u64) * 10_000;

    let exe = r"C:\Users\Alice\Downloads\policy_rollback_sweep.exe";
    let permit_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));

    // 1. Start and stop `exe` with remove failure on its Preemptive handle so it enters
    //    `pending_preemptive_removals`.
    let hp = engine.high_priority_processed.load(Ordering::Relaxed);
    sender
        .send(SensorEvent::ProcessStart {
            identity: ProcessIdentity::new(9410, base_100ns),
            parent_pid: 4,
            exe_path: exe.to_string(),
            command_line: "policy_rollback_sweep.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("start exe");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while engine.high_priority_processed.load(Ordering::Relaxed) < hp + 1 {
        assert!(tokio::time::Instant::now() < deadline, "start exe");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let preempt_handle = {
        let fw = engine.firewall.lock().unwrap_or_else(|e| e.into_inner());
        let (h, origin) = fw
            .active_app_block(exe)
            .expect("Preemptive block installed");
        assert_eq!(origin, WfpFilterOrigin::Preemptive);
        h
    };
    defense.set_fail_handle(preempt_handle, true);

    let hp = engine.high_priority_processed.load(Ordering::Relaxed);
    sender
        .send(SensorEvent::ProcessStop {
            pid: 9410,
            exit_time_100ns: base_100ns + 10_000,
            exit_code: 0,
        })
        .await
        .expect("stop exe");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while engine.high_priority_processed.load(Ordering::Relaxed) < hp + 1 {
        assert!(tokio::time::Instant::now() < deadline, "stop exe");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // 2. Install a `DomainPolicy` Permit on `(exe, permit_ip)` and inject BFE remove failure on
    //    that permit handle so an app-wide `NetworkBlock` upsert promotes `preempt_handle` and
    //    then fails removing the conflicting `DomainPolicy` Permit, triggering SQLite + WFP
    //    rollback.
    let permit_handle = {
        let mut fw = engine.firewall.lock().unwrap_or_else(|e| e.into_inner());
        assert!(fw.has_pending_preemptive_removal(exe));
        fw.ensure_ip_permit_for_domain_hints_prioritized(
            exe,
            permit_ip,
            &["cdn.example.com"],
            &[] as &[&str],
            &*engine.defense,
        )
        .expect("install DomainPolicy permit")
        .expect("new permit handle")
    };
    defense.set_fail_handle(permit_handle, true);

    let block_rule = AllowlistRuleRecord {
        rule_id: "R-BLK-ROLLBACK-02".to_string(),
        scope: RuleScope::NetworkBlock,
        exe_path_pattern: exe.to_string(),
        sha256: None,
        signer_subject: None,
        root_thumbprint: None,
        allowed_target: None,
        created_at_ms: now_ms,
        created_by: "test".to_string(),
    };
    let err = engine
        .upsert_policy_rule(&block_rule)
        .expect_err("failed DomainPolicy permit removal must roll back NetworkBlock upsert");
    assert!(
        matches!(err, PolicyRuleError::FirewallSync(_)),
        "expected FirewallSync rollback error, got: {err:?}"
    );
    assert!(
        engine
            .store
            .get_rule(&block_rule.rule_id)
            .expect("get_rule")
            .is_none(),
        "failed policy edit must be rolled back in SQLite"
    );

    // 3. Verify rollback restored BOTH `WfpFilterOrigin::Preemptive` AND
    //    `pending_preemptive_removals` so periodic sweep cleans up once BFE recovers.
    {
        let fw = engine.firewall.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(
            fw.filter_origin(exe, None),
            Some(&WfpFilterOrigin::Preemptive),
            "rollback must restore Preemptive origin"
        );
        assert!(
            fw.has_pending_preemptive_removal(exe),
            "rollback must restore pending_preemptive_removals entry cleared during promotion"
        );
    }

    defense.set_fail_handle(preempt_handle, false);
    let sweep_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while try_has_active_wfp_filter(&engine, exe, None, false, Duration::from_secs(2))
        .await
        .expect("fw lock")
    {
        assert!(
            tokio::time::Instant::now() < sweep_deadline,
            "periodic sweep must remove restored pending-removal Preemptive block after BFE recovery"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    engine.shutdown_and_flush().await.expect("shutdown engine");
}

/// Regression test `WFP-DEFERRED-03` (`PRRT_kwDOVyjVyM66ksZW`):
/// verifies that when a still-running sibling (`A1`) of an unapproved executable is evicted from
/// `ActiveProcessTable::entries` BEFORE another sibling (`A2`) stops and resolves the last bound
/// network alert (via sibling auto-resolve), `A1`'s `Preemptive` WFP block stays intact — and is
/// only removed once `A1` itself actually stops. Also verifies scoped `AllowPermanent` after
/// `ProcessStop` removes a deferred block, while secondary `evicted_live` overflow stays fail-closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn evicted_live_sibling_retains_preemptive_block_across_last_alert_resolution_until_stop() {
    use std::collections::HashSet;
    use std::time::Duration;

    use crate::firewall::{WfpFilterOrigin, WfpRuleManager};
    use crate::process_table::ActiveProcessTable;

    struct TrackingDefense {
        next_handle: AtomicU64,
        active_handles: Mutex<HashSet<u64>>,
    }

    impl TrackingDefense {
        fn new() -> Self {
            Self {
                next_handle: AtomicU64::new(9500),
                active_handles: Mutex::new(HashSet::new()),
            }
        }

        fn active_handles(&self) -> HashSet<u64> {
            self.active_handles
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
    }

    impl ActiveDefenseController for TrackingDefense {
        fn suspend_process(&self, _: &ProcessIdentity, _: bool) -> Result<(), String> {
            Ok(())
        }
        fn resume_process(&self, _: &ProcessIdentity) -> Result<(), String> {
            Ok(())
        }
        fn terminate_process(&self, _: &ProcessIdentity, _: bool) -> Result<(), String> {
            Ok(())
        }
        fn add_wfp_app_rule(
            &self,
            _: &Path,
            _: Option<IpAddr>,
            _: bool,
        ) -> Result<u64, String> {
            let h = self.next_handle.fetch_add(1, Ordering::Relaxed);
            self.active_handles
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(h);
            Ok(h)
        }
        fn remove_wfp_rule(&self, handle: u64) -> Result<(), String> {
            self.active_handles
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&handle);
            Ok(())
        }
    }

    let defense = Arc::new(TrackingDefense::new());
    let store = LedrStore::open_in_memory().expect("in-memory store");
    let engine = DaemonEngine::start_with_all_dependencies(
        store,
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::Enforce,
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(StubNotifier),
        Arc::new(FixedShaInspector("e".repeat(64))),
        Arc::new(MapLiveProcessInspector::new([])),
    );
    {
        let mut table = engine
            .process_table
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *table = ActiveProcessTable::new(2);
    }
    let sender = engine.sender();

    let now_ms = current_unix_ms();
    let base_100ns = 116_444_736_000_000_000u64 + ((now_ms - 5_000) as u64) * 10_000;
    let wait_hp = |target: u64| {
        let eng = Arc::clone(&engine);
        async move {
            let dl = tokio::time::Instant::now() + Duration::from_secs(5);
            while eng.high_priority_processed.load(Ordering::Relaxed) < target {
                assert!(tokio::time::Instant::now() < dl, "hp target {target}");
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    };

    // --- Part A: A1 is evicted BEFORE A2 stops and resolves the last bound alert ---
    let exe_a = r"C:\Users\Alice\Downloads\evicted_before_stop.exe";
    let id_a1 = ProcessIdentity::new(9510, base_100ns);
    let id_a2 = ProcessIdentity::new(9511, base_100ns + 10_000);
    let inst_a2 = id_a2.instance_id();

    let hp = engine.high_priority_processed.load(Ordering::Relaxed);
    sender
        .send(SensorEvent::ProcessStart {
            identity: id_a1,
            parent_pid: 4,
            exe_path: exe_a.to_string(),
            command_line: "evicted_before_stop.exe --live-1".to_string(),
            user_sid: None,
        })
        .await
        .expect("start A1");
    sender
        .send(SensorEvent::ProcessStart {
            identity: id_a2,
            parent_pid: 4,
            exe_path: exe_a.to_string(),
            command_line: "evicted_before_stop.exe --worker-2".to_string(),
            user_sid: None,
        })
        .await
        .expect("start A2");
    wait_hp(hp + 2).await;

    // Evict still-running A1 from `ActiveProcessTable::entries` (cap=2) BEFORE A2 exits.
    let hp = engine.high_priority_processed.load(Ordering::Relaxed);
    sender
        .send(SensorEvent::ProcessStart {
            identity: ProcessIdentity::new(9512, base_100ns + 20_000),
            parent_pid: 4,
            exe_path: r"C:\Program Files\BenignPad\pad_a1.exe".to_string(),
            command_line: "pad_a1.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("start pad_a1");
    wait_hp(hp + 1).await;
    {
        let table = engine
            .process_table
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        assert!(
            table.get_by_instance_id(&id_a1.instance_id()).is_none(),
            "A1 must be evicted from primary entries"
        );
        assert!(
            table.has_active_exe_key(&WfpRuleManager::exe_key(exe_a)),
            "evicted live A1 must remain active in has_active_exe_key"
        );
    }

    let alert_a_rule = AlertRecord {
        alert_id: "ALT-EVICT-A-RULE".to_string(),
        timestamp_ms: now_ms,
        severity: AlertSeverity::High,
        source_layer: "LAYER_1_PROCESS".to_string(),
        rule_id: "SIGMA-EVICT-A".to_string(),
        title: "Rule alert on A2".to_string(),
        process_instance_id: Some(inst_a2.clone()),
        process_suspended: false,
        status: AlertStatus::Pending,
        context_json: serde_json::json!({
            "exe_path": exe_a,
            "sha256": "e".repeat(64),
        })
        .to_string(),
        resolved_at_ms: None,
    };
    let alert_a_net = AlertRecord {
        alert_id: "ALT-EVICT-A-NET".to_string(),
        timestamp_ms: now_ms,
        severity: AlertSeverity::High,
        source_layer: "LAYER_3_NETWORK".to_string(),
        rule_id: "WFP-PREEMPT-EVICT-A".to_string(),
        title: "Network alert on A2".to_string(),
        process_instance_id: Some(inst_a2.clone()),
        process_suspended: false,
        status: AlertStatus::Pending,
        context_json: serde_json::json!({
            "exe_path": exe_a,
            "sha256": "e".repeat(64),
        })
        .to_string(),
        resolved_at_ms: None,
    };
    engine.store.record_alert(&alert_a_rule).expect("record rule");
    engine.store.record_alert(&alert_a_net).expect("record net");
    {
        let mut fw = engine.firewall.lock().unwrap_or_else(|e| e.into_inner());
        assert!(fw.bind_alert_to_app_block(&alert_a_net.alert_id, exe_a));
    }

    // A2 exits while evicted live A1 is STILL running -> must NOT strip block or mark deferred.
    let hp = engine.high_priority_processed.load(Ordering::Relaxed);
    sender
        .send(SensorEvent::ProcessStop {
            pid: id_a2.pid,
            exit_time_100ns: base_100ns + 30_000,
            exit_code: 0,
        })
        .await
        .expect("stop A2");
    wait_hp(hp + 1).await;

    // Resolving A2's rule alert auto-resolves A2's bound network alert; A1's Preemptive block
    // MUST remain active because A1 is still running!
    engine
        .resolve_alert(
            &alert_a_rule.alert_id,
            ledr_proto::AlertDecision::TerminateAndBlock {
                add_block_rule: false,
            },
        )
        .expect("resolve rule alert on A2");
    {
        let fw = engine.firewall.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(
            fw.filter_origin(exe_a, None),
            Some(&WfpFilterOrigin::Preemptive),
            "still-running evicted A1 must keep its Preemptive WFP block after A2's last alert resolves"
        );
        assert!(!fw.has_deferred_preemptive_removal(exe_a));
        assert!(!fw.has_pending_preemptive_removal(exe_a));
    }

    // Now A1 itself finally stops -> `on_process_stop_with_exe` resolves A1 from `evicted_live`
    // and cleanly removes `exe_a`'s Preemptive WFP block!
    let hp = engine.high_priority_processed.load(Ordering::Relaxed);
    sender
        .send(SensorEvent::ProcessStop {
            pid: id_a1.pid,
            exit_time_100ns: base_100ns + 40_000,
            exit_code: 0,
        })
        .await
        .expect("stop A1");
    wait_hp(hp + 1).await;
    {
        let fw = engine.firewall.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            !fw.has_any_app_filter(exe_a),
            "stopping evicted live A1 must cleanly remove exe_a's Preemptive WFP block"
        );
    }
    assert!(defense.active_handles().is_empty());

    // --- Part B: Scoped AllowPermanent after ProcessStop cleans up deferred Preemptive block,
    //     while secondary `evicted_live` overflow stays fail-closed for a running sibling ---
    let exe_scoped = r"C:\Users\Alice\Downloads\scoped_allow_after_stop.exe";
    let id_s1 = ProcessIdentity::new(9520, base_100ns + 50_000);
    let hp = engine.high_priority_processed.load(Ordering::Relaxed);
    sender
        .send(SensorEvent::ProcessStart {
            identity: id_s1,
            parent_pid: 4,
            exe_path: exe_scoped.to_string(),
            command_line: "scoped_allow_after_stop.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("start S1");
    wait_hp(hp + 1).await;

    let alert_scoped = AlertRecord {
        alert_id: "ALT-SCOPED-AFTER-STOP".to_string(),
        timestamp_ms: now_ms,
        severity: AlertSeverity::High,
        source_layer: "LAYER_3_NETWORK".to_string(),
        rule_id: "WFP-PREEMPT-SCOPED".to_string(),
        title: "Scoped network alert".to_string(),
        process_instance_id: Some(id_s1.instance_id()),
        process_suspended: false,
        status: AlertStatus::Pending,
        context_json: serde_json::json!({
            "exe_path": exe_scoped,
            "sha256": "e".repeat(64),
            "dst_ip": "198.51.100.42",
        })
        .to_string(),
        resolved_at_ms: None,
    };
    engine
        .store
        .record_alert(&alert_scoped)
        .expect("record scoped alert");
    {
        let mut fw = engine.firewall.lock().unwrap_or_else(|e| e.into_inner());
        assert!(fw.bind_alert_to_app_block(&alert_scoped.alert_id, exe_scoped));
    }
    let hp = engine.high_priority_processed.load(Ordering::Relaxed);
    sender
        .send(SensorEvent::ProcessStop {
            pid: id_s1.pid,
            exit_time_100ns: base_100ns + 60_000,
            exit_code: 0,
        })
        .await
        .expect("stop S1");
    wait_hp(hp + 1).await;
    {
        let fw = engine.firewall.lock().unwrap_or_else(|e| e.into_inner());
        assert!(fw.has_deferred_preemptive_removal(exe_scoped));
    }
    engine
        .resolve_alert(
            &alert_scoped.alert_id,
            ledr_proto::AlertDecision::AllowPermanent {
                use_signer_if_available: false,
                allow_dest: Some("198.51.100.42".to_string()),
            },
        )
        .expect("resolve scoped AllowPermanent");
    {
        let fw = engine.firewall.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            !fw.has_active_filter(exe_scoped, None, false),
            "scoped AllowPermanent releasing last bound alert after ProcessStop must remove deferred Preemptive block"
        );
    }

    // Secondary `evicted_live` overflow fail-closed check: even when `evicted_live` overflows,
    // `retry_deferred_preemptive_removal_locked` refuses to strip the overflowed exe's block.
    {
        let mut table = engine
            .process_table
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *table = ActiveProcessTable::new(1).with_evicted_live_capacity(1);
    }
    let exe_ov = r"C:\Users\Alice\Downloads\overflow_protected.exe";
    let hp = engine.high_priority_processed.load(Ordering::Relaxed);
    sender
        .send(SensorEvent::ProcessStart {
            identity: ProcessIdentity::new(9530, base_100ns + 70_000),
            parent_pid: 4,
            exe_path: exe_ov.to_string(),
            command_line: "overflow_protected.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("start ov");
    sender
        .send(SensorEvent::ProcessStart {
            identity: ProcessIdentity::new(9531, base_100ns + 80_000),
            parent_pid: 4,
            exe_path: r"C:\Program Files\BenignPad\ov_pad1.exe".to_string(),
            command_line: "ov_pad1.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("start ov_pad1");
    sender
        .send(SensorEvent::ProcessStart {
            identity: ProcessIdentity::new(9532, base_100ns + 90_000),
            parent_pid: 4,
            exe_path: r"C:\Program Files\BenignPad\ov_pad2.exe".to_string(),
            command_line: "ov_pad2.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("start ov_pad2");
    wait_hp(hp + 3).await;
    {
        let mut fw = engine.firewall.lock().unwrap_or_else(|e| e.into_inner());
        assert!(fw.bind_alert_to_app_block("ALT-OV-TEMP", exe_ov));
        assert!(!fw.remove_preemptive_block_if_unused(exe_ov, &*engine.defense));
        assert!(fw.has_deferred_preemptive_removal(exe_ov));
        fw.unbind_alert("ALT-OV-TEMP");
        engine.retry_deferred_preemptive_removal_locked(&mut fw, exe_ov);
        assert_eq!(
            fw.filter_origin(exe_ov, None),
            Some(&WfpFilterOrigin::Preemptive),
            "secondary evicted_live overflow must keep Preemptive block intact (fail-closed)"
        );
        assert!(!fw.has_deferred_preemptive_removal(exe_ov));
    }

    engine.shutdown_and_flush().await.expect("shutdown engine");
}

/// Regression test `WFP-ROLLBACK-04` (`PRRT_kwDOVyjVyM66ksZF`):
/// verifies that when app-wide `AllowPermanent` (or `AllowOnce`) removes a deferred-removal
/// `Preemptive` block and subsequently fails during alert resolution (rolling back the saved rule
/// and restoring the block + bindings), the restored `Preemptive` block retains its
/// `deferred_preemptive_removals` state so a subsequent sibling alert auto-resolve cleanly deletes
/// the restored filter from BFE.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn allow_permanent_and_allow_once_rollback_preserve_deferred_preemptive_removal() {
    use std::collections::HashSet;
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

    use crate::firewall::WfpFilterOrigin;

    struct FailResumeDefense {
        next_handle: AtomicU64,
        fail_resume: AtomicBool,
        active_handles: Mutex<HashSet<u64>>,
    }

    impl FailResumeDefense {
        fn new() -> Self {
            Self {
                next_handle: AtomicU64::new(9600),
                fail_resume: AtomicBool::new(false),
                active_handles: Mutex::new(HashSet::new()),
            }
        }

        fn active_handles(&self) -> HashSet<u64> {
            self.active_handles
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
    }

    impl ActiveDefenseController for FailResumeDefense {
        fn suspend_process(&self, _: &ProcessIdentity, _: bool) -> Result<(), String> {
            Ok(())
        }
        fn resume_process(&self, target: &ProcessIdentity) -> Result<(), String> {
            if self.fail_resume.load(Ordering::Acquire) {
                return Err(format!(
                    "simulated access denied resuming PID {}",
                    target.pid
                ));
            }
            Ok(())
        }
        fn terminate_process(&self, _: &ProcessIdentity, _: bool) -> Result<(), String> {
            Ok(())
        }
        fn add_wfp_app_rule(
            &self,
            _: &Path,
            _: Option<IpAddr>,
            _: bool,
        ) -> Result<u64, String> {
            let h = self.next_handle.fetch_add(1, Ordering::Relaxed);
            self.active_handles
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(h);
            Ok(h)
        }
        fn remove_wfp_rule(&self, handle: u64) -> Result<(), String> {
            self.active_handles
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&handle);
            Ok(())
        }
    }

    let defense = Arc::new(FailResumeDefense::new());
    let store = LedrStore::open_in_memory().expect("in-memory store");
    let engine = DaemonEngine::start_with_all_dependencies(
        store,
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::Enforce,
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(StubNotifier),
        Arc::new(FixedShaInspector("f".repeat(64))),
        Arc::new(MapLiveProcessInspector::new([])),
    );
    let sender = engine.sender();

    let now_ms = current_unix_ms();
    let base_100ns = 116_444_736_000_000_000u64 + ((now_ms - 5_000) as u64) * 10_000;
    let exe = r"C:\Users\Alice\Downloads\allow_perm_rollback_deferred.exe";
    let proc_id = ProcessIdentity::new(9610, base_100ns);
    let proc_inst = proc_id.instance_id();

    let hp = engine.high_priority_processed.load(Ordering::Relaxed);
    sender
        .send(SensorEvent::ProcessStart {
            identity: proc_id,
            parent_pid: 4,
            exe_path: exe.to_string(),
            command_line: "allow_perm_rollback_deferred.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("start proc");
    let dl = tokio::time::Instant::now() + Duration::from_secs(5);
    while engine.high_priority_processed.load(Ordering::Relaxed) < hp + 1 {
        assert!(tokio::time::Instant::now() < dl, "start processed");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // Use the current process PID as a live `suspended_children` entry so
    // `is_process_gone_or_replaced` confirms `Running` and treats `resume_process` failure as a
    // fatal rollback error.
    let live_child = ProcessIdentity::new(std::process::id(), 1);
    let alert_rule = AlertRecord {
        alert_id: "ALT-RB4-RULE".to_string(),
        timestamp_ms: now_ms,
        severity: AlertSeverity::High,
        source_layer: "LAYER_1_PROCESS".to_string(),
        rule_id: "SIGMA-RB4".to_string(),
        title: "Rule alert RB4".to_string(),
        process_instance_id: Some(proc_inst.clone()),
        process_suspended: false,
        status: AlertStatus::Pending,
        context_json: serde_json::json!({
            "exe_path": exe,
            "sha256": "f".repeat(64),
        })
        .to_string(),
        resolved_at_ms: None,
    };
    let alert_net = AlertRecord {
        alert_id: "ALT-RB4-NET".to_string(),
        timestamp_ms: now_ms,
        severity: AlertSeverity::High,
        source_layer: "LAYER_3_NETWORK".to_string(),
        rule_id: "WFP-PREEMPT-RB4".to_string(),
        title: "Network alert RB4".to_string(),
        process_instance_id: Some(proc_inst.clone()),
        process_suspended: true,
        status: AlertStatus::Pending,
        context_json: serde_json::json!({
            "exe_path": exe,
            "sha256": "f".repeat(64),
            "suspended_children": [live_child.instance_id()],
        })
        .to_string(),
        resolved_at_ms: None,
    };
    engine.store.record_alert(&alert_rule).expect("record rule");
    engine.store.record_alert(&alert_net).expect("record net");
    {
        let mut fw = engine.firewall.lock().unwrap_or_else(|e| e.into_inner());
        assert!(fw.bind_alert_to_app_block(&alert_net.alert_id, exe));
    }

    // Process exits -> `remove_preemptive_block_if_unused` defers removal while ALT-RB4-NET is bound.
    let hp = engine.high_priority_processed.load(Ordering::Relaxed);
    sender
        .send(SensorEvent::ProcessStop {
            pid: proc_id.pid,
            exit_time_100ns: base_100ns + 10_000,
            exit_code: 0,
        })
        .await
        .expect("stop proc");
    let dl = tokio::time::Instant::now() + Duration::from_secs(5);
    while engine.high_priority_processed.load(Ordering::Relaxed) < hp + 1 {
        assert!(tokio::time::Instant::now() < dl, "stop processed");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    {
        let fw = engine.firewall.lock().unwrap_or_else(|e| e.into_inner());
        assert!(fw.has_deferred_preemptive_removal(exe));
    }

    // 1. Fail app-wide `AllowPermanent` after reconcile removes the Preemptive block and installs
    //    PersistedPolicy Permit -> rollback must restore Preemptive block, ALT-RB4-NET binding,
    //    AND `deferred_preemptive_removals`!
    defense.fail_resume.store(true, Ordering::Release);
    let perm_err = engine
        .resolve_alert(
            &alert_net.alert_id,
            ledr_proto::AlertDecision::AllowPermanent {
                use_signer_if_available: false,
                allow_dest: None,
            },
        )
        .expect_err("app-wide AllowPermanent must fail and roll back when resume fails");
    assert!(
        perm_err.contains("simulated access denied"),
        "unexpected error: {perm_err}"
    );
    {
        let fw = engine.firewall.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(
            fw.filter_origin(exe, None),
            Some(&WfpFilterOrigin::Preemptive),
            "AllowPermanent rollback must restore Preemptive block"
        );
        assert!(
            fw.is_alert_bound(&alert_net.alert_id),
            "AllowPermanent rollback must rebind alert"
        );
        assert!(
            fw.has_deferred_preemptive_removal(exe),
            "AllowPermanent rollback must preserve deferred_preemptive_removals on restored block"
        );
    }

    // 2. Also fail `AllowOnce` (which lifts the Preemptive block directly via
    //    `lift_block_for_allow_once`) -> rollback must likewise preserve `deferred_preemptive_removals`!
    let once_err = engine
        .resolve_alert(&alert_net.alert_id, ledr_proto::AlertDecision::AllowOnce)
        .expect_err("AllowOnce must fail and roll back when resume fails");
    assert!(
        once_err.contains("simulated access denied"),
        "unexpected error: {once_err}"
    );
    {
        let fw = engine.firewall.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(
            fw.filter_origin(exe, None),
            Some(&WfpFilterOrigin::Preemptive),
            "AllowOnce rollback must restore Preemptive block"
        );
        assert!(
            fw.is_alert_bound(&alert_net.alert_id),
            "AllowOnce rollback must rebind alert"
        );
        assert!(
            fw.has_deferred_preemptive_removal(exe),
            "AllowOnce rollback must preserve deferred_preemptive_removals on restored block"
        );
    }

    // 3. Resolve the sibling rule alert via `TerminateAndBlock { add_block_rule: false }`
    //    (auto-resolving `ALT-RB4-NET` via `resolve_sibling_alerts_as_terminated`) ->
    //    the restored deferred Preemptive block MUST be cleanly removed from BFE!
    defense.fail_resume.store(false, Ordering::Release);
    engine
        .resolve_alert(
            &alert_rule.alert_id,
            ledr_proto::AlertDecision::TerminateAndBlock {
                add_block_rule: false,
            },
        )
        .expect("resolve sibling rule alert");
    {
        let fw = engine.firewall.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            !fw.has_any_app_filter(exe),
            "auto-resolving last sibling alert after rollback must remove restored deferred Preemptive block"
        );
        assert!(!fw.has_deferred_preemptive_removal(exe));
    }
    assert!(
        defense.active_handles().is_empty(),
        "no BFE handle may leak after sibling resolution following rollback"
    );

    engine.shutdown_and_flush().await.expect("shutdown engine");
}

/// Regression test `WFP-ROLLBACK-06` (`PRRT_kwDOVyjVyM66k6kK`):
/// verifies end-to-end through `DaemonEngine::upsert_policy_rule` that:
/// 1. When an app-wide `NetworkAllow` removes a non-startup unbound `Preemptive` block and then
///    fails to add the Permit filter, if the last process exits before rollback restores removed
///    app blocks, rollback skips resurrecting the dead `Preemptive` block (0 BFE handles left).
/// 2. When the process is still active during rollback, rollback restores the `Preemptive` block
///    AND releases `process_table` BEFORE invoking `defense.add_wfp_app_rule` (verified via
///    `process_table.try_lock().is_ok()` inside the BFE mock).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upsert_policy_rule_rollback_skips_preemptive_restore_after_last_process_exit_and_unlocks_table_before_bfe() {
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::time::Duration;

    use crate::firewall::WfpRuleManager;
    use crate::PolicyRuleError;
    use ledr_proto::AllowlistRuleRecord;

    struct RollbackLivenessDefense {
        next_handle: AtomicU64,
        active: Mutex<HashSet<u64>>,
        fail_permit_adds: AtomicBool,
        permit_add_attempts: AtomicUsize,
        block_add_attempts: AtomicUsize,
        on_permit_fail_hook: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
        on_block_add_hook: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
    }

    impl RollbackLivenessDefense {
        fn new() -> Self {
            Self {
                next_handle: AtomicU64::new(400),
                active: Mutex::new(HashSet::new()),
                fail_permit_adds: AtomicBool::new(false),
                permit_add_attempts: AtomicUsize::new(0),
                block_add_attempts: AtomicUsize::new(0),
                on_permit_fail_hook: Mutex::new(None),
                on_block_add_hook: Mutex::new(None),
            }
        }

        fn active_handles(&self) -> Vec<u64> {
            self.active.lock().unwrap().iter().copied().collect()
        }
    }

    impl ActiveDefenseController for RollbackLivenessDefense {
        fn suspend_process(&self, _: &ProcessIdentity, _: bool) -> Result<(), String> {
            Ok(())
        }
        fn resume_process(&self, _: &ProcessIdentity) -> Result<(), String> {
            Ok(())
        }
        fn terminate_process(&self, _: &ProcessIdentity, _: bool) -> Result<(), String> {
            Ok(())
        }
        fn add_wfp_app_rule(
            &self,
            _exe_path: &Path,
            _remote_ip: Option<IpAddr>,
            allow: bool,
        ) -> Result<u64, String> {
            if allow {
                self.permit_add_attempts.fetch_add(1, Ordering::AcqRel);
                if self.fail_permit_adds.load(Ordering::Acquire) {
                    if let Some(ref hook) = *self.on_permit_fail_hook.lock().unwrap() {
                        hook();
                    }
                    return Err("simulated BFE permit add failure".to_string());
                }
            } else {
                self.block_add_attempts.fetch_add(1, Ordering::AcqRel);
                if let Some(ref hook) = *self.on_block_add_hook.lock().unwrap() {
                    hook();
                }
            }
            let h = self.next_handle.fetch_add(1, Ordering::Relaxed);
            self.active.lock().unwrap().insert(h);
            Ok(h)
        }
        fn remove_wfp_rule(&self, handle: u64) -> Result<(), String> {
            self.active.lock().unwrap().remove(&handle);
            Ok(())
        }
    }

    let defense = Arc::new(RollbackLivenessDefense::new());
    let store = LedrStore::open_in_memory().expect("in-memory store");
    let engine = Arc::new(DaemonEngine::start_with_all_dependencies(
        store,
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::Enforce,
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(StubNotifier),
        Arc::new(FixedShaInspector("c".repeat(64))),
        Arc::new(MapLiveProcessInspector::new([])),
    ));
    let sender = engine.sender();

    let now_ms = current_unix_ms();
    let base_100ns = 116_444_736_000_000_000u64 + ((now_ms - 5_000) as u64) * 10_000;

    // --- Part 1: Last process exits before rollback restores removed Preemptive block ---
    let exe_dead = r"C:\Users\Alice\Downloads\rb6_exited_during_allow.exe";
    let pid_dead = ProcessIdentity::new(9651, base_100ns);
    let hp = engine.high_priority_processed.load(Ordering::Relaxed);
    sender
        .send(SensorEvent::ProcessStart {
            identity: pid_dead,
            parent_pid: 4,
            exe_path: exe_dead.to_string(),
            command_line: "rb6_exited.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("start exe_dead");
    let dl = tokio::time::Instant::now() + Duration::from_secs(5);
    while engine.high_priority_processed.load(Ordering::Relaxed) < hp + 1 {
        assert!(tokio::time::Instant::now() < dl, "exe_dead start");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        try_has_active_wfp_filter(&engine, exe_dead, None, false, Duration::from_secs(2))
            .await
            .expect("firewall lock")
    );

    // When `add_wfp_app_rule(..., allow = true)` fails (after reconcile has already removed the
    // Preemptive block), enqueue `ProcessStop` and wait until `process_table` records the exit
    // (proving `process_table` is unlocked during reconcile and the exit happens prior to
    // `restore_removed_app_blocks`).
    let stop_tx = sender.clone();
    let engine_hook = Arc::clone(&engine);
    let dead_key = WfpRuleManager::exe_key(exe_dead);
    let stop_time_100ns = base_100ns + 20_000;
    *defense.on_permit_fail_hook.lock().unwrap() = Some(Box::new(move || {
        assert_eq!(
            tokio::runtime::Handle::current().runtime_flavor(),
            tokio::runtime::RuntimeFlavor::MultiThread,
            "block_in_place hook requires multi-threaded Tokio runtime"
        );
        tokio::task::block_in_place(|| {
            stop_tx
                .try_send(SensorEvent::ProcessStop {
                    pid: pid_dead.pid,
                    exit_time_100ns: stop_time_100ns,
                    exit_code: 0,
                })
                .expect("enqueue ProcessStop for exe_dead");
            let wait_dl = std::time::Instant::now() + Duration::from_secs(5);
            let mut ever_acquired_table_lock = false;
            loop {
                match engine_hook.process_table.try_lock() {
                    Ok(table) => {
                        ever_acquired_table_lock = true;
                        if !table.has_active_exe_key(&dead_key) {
                            break;
                        }
                    }
                    Err(std::sync::TryLockError::Poisoned(e)) => {
                        ever_acquired_table_lock = true;
                        if !e.into_inner().has_active_exe_key(&dead_key) {
                            break;
                        }
                    }
                    Err(std::sync::TryLockError::WouldBlock) => {}
                }
                assert!(
                    std::time::Instant::now() < wait_dl,
                    "timed out waiting for ProcessStop to update process_table while reconcile \
                     fails permit add (ever_acquired_table_lock={ever_acquired_table_lock}; \
                     false indicates process_table lock was held across BFE permit add)"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
        });
    }));

    let block_adds_before_dead_rb = defense.block_add_attempts.load(Ordering::Acquire);
    let hp_before_stop = engine.high_priority_processed.load(Ordering::Relaxed);
    defense.fail_permit_adds.store(true, Ordering::Release);
    let allow_dead = AllowlistRuleRecord {
        rule_id: "R-RB6-DEAD".to_string(),
        scope: RuleScope::NetworkAllow,
        exe_path_pattern: exe_dead.to_string(),
        sha256: Some("c".repeat(64)),
        signer_subject: None,
        root_thumbprint: None,
        allowed_target: None,
        created_at_ms: now_ms,
        created_by: "test".to_string(),
    };
    let err = engine
        .upsert_policy_rule(&allow_dead)
        .expect_err("upsert_policy_rule must fail and roll back when permit add fails");
    assert!(
        matches!(err, PolicyRuleError::FirewallSync(_)),
        "expected FirewallSync error, got {err:?}"
    );
    *defense.on_permit_fail_hook.lock().unwrap() = None;

    // Wait for the concurrent `ProcessStop` event to finish its firewall path too.
    let dl = tokio::time::Instant::now() + Duration::from_secs(5);
    while engine.high_priority_processed.load(Ordering::Relaxed) < hp_before_stop + 1 {
        assert!(tokio::time::Instant::now() < dl, "exe_dead stop finished");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    assert_eq!(
        defense.block_add_attempts.load(Ordering::Acquire),
        block_adds_before_dead_rb,
        "rollback must NOT call add_wfp_app_rule to resurrect dead unbound Preemptive block"
    );
    assert!(
        !try_has_active_wfp_filter(&engine, exe_dead, None, false, Duration::from_secs(2))
            .await
            .expect("firewall lock"),
        "exited app must have no resurrected Preemptive WFP filter after rollback"
    );
    assert!(
        defense.active_handles().is_empty(),
        "zero OS BFE handles must remain after dead app rollback"
    );

    // --- Part 2: Still-active process MUST be restored, with `process_table` unlocked during BFE ---
    let exe_live = r"C:\Users\Alice\Downloads\rb6_live_during_allow.exe";
    let pid_live = ProcessIdentity::new(9652, base_100ns + 30_000);
    let hp = engine.high_priority_processed.load(Ordering::Relaxed);
    sender
        .send(SensorEvent::ProcessStart {
            identity: pid_live,
            parent_pid: 4,
            exe_path: exe_live.to_string(),
            command_line: "rb6_live.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("start exe_live");
    let dl = tokio::time::Instant::now() + Duration::from_secs(5);
    while engine.high_priority_processed.load(Ordering::Relaxed) < hp + 1 {
        assert!(tokio::time::Instant::now() < dl, "exe_live start");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        try_has_active_wfp_filter(&engine, exe_live, None, false, Duration::from_secs(2))
            .await
            .expect("firewall lock")
    );

    let table_unlocked_during_bfe = Arc::new(AtomicBool::new(false));
    let flag_hook = Arc::clone(&table_unlocked_during_bfe);
    let engine_bfe_hook = Arc::clone(&engine);
    *defense.on_block_add_hook.lock().unwrap() = Some(Box::new(move || {
        assert!(
            engine_bfe_hook.process_table.try_lock().is_ok(),
            "process_table lock MUST be released before BFE add_wfp_app_rule during rollback"
        );
        flag_hook.store(true, Ordering::Release);
    }));

    let allow_live = AllowlistRuleRecord {
        rule_id: "R-RB6-LIVE".to_string(),
        scope: RuleScope::NetworkAllow,
        exe_path_pattern: exe_live.to_string(),
        sha256: Some("c".repeat(64)),
        signer_subject: None,
        root_thumbprint: None,
        allowed_target: None,
        created_at_ms: now_ms + 1,
        created_by: "test".to_string(),
    };
    let err_live = engine
        .upsert_policy_rule(&allow_live)
        .expect_err("upsert_policy_rule must fail and roll back");
    assert!(matches!(err_live, PolicyRuleError::FirewallSync(_)));
    *defense.on_block_add_hook.lock().unwrap() = None;

    assert!(
        table_unlocked_during_bfe.load(Ordering::Acquire),
        "rollback must have restored active exe_live via add_wfp_app_rule with process_table unlocked"
    );
    assert!(
        try_has_active_wfp_filter(&engine, exe_live, None, false, Duration::from_secs(2))
            .await
            .expect("firewall lock"),
        "still-active app must retain its restored Preemptive block after rollback"
    );

    let engine = Arc::try_unwrap(engine)
        .ok()
        .expect("single owner before shutdown");
    engine.shutdown_and_flush().await.expect("shutdown engine");
}

/// Regression test `E2E-PREEMPT-01` (`PRRT_kwDOVyjVyM66k6ks`):
/// verifies end-to-end that when an evicted-live process in a normal folder receives a Preemptive
/// WFP block via delayed MOTW attribution (`apply_late_motw_attribution`) and its `ProcessStop`
/// arrives late (or is missed) after another executable reuses its PID:
/// 1. Processing the successor `ProcessStart` runs `ProcessStop`-equivalent cleanup for the
///    superseded evicted-live executable and removes its unused Preemptive WFP block immediately.
/// 2. If the superseded executable still has a bound pending alert, cleanup marks
///    `deferred_preemptive_removals` instead of dropping the block early, and resolving the alert
///    removes the block cleanly.
/// 3. If another sibling instance of the superseded executable is still running, the Preemptive
///    WFP block remains active.
#[tokio::test]
async fn pid_reuse_of_evicted_live_late_motw_process_cleans_up_preemptive_block_and_respects_alerts_and_siblings() {
    use std::collections::HashSet;
    use std::time::Duration;

    use crate::engine::motw::{LateMotwAttribution, MotwAttribution, MotwMatchStage};
    use crate::firewall::WfpRuleManager;
    use crate::process_table::ActiveProcessTable;
    use crate::TwoLaneSender;

    struct HandleTrackingDefense {
        next_handle: AtomicU64,
        active: Mutex<HashSet<u64>>,
    }

    impl HandleTrackingDefense {
        fn new() -> Self {
            Self {
                next_handle: AtomicU64::new(700),
                active: Mutex::new(HashSet::new()),
            }
        }

        fn active_handles(&self) -> HashSet<u64> {
            self.active.lock().unwrap().clone()
        }
    }

    impl ActiveDefenseController for HandleTrackingDefense {
        fn suspend_process(&self, _: &ProcessIdentity, _: bool) -> Result<(), String> {
            Ok(())
        }
        fn resume_process(&self, _: &ProcessIdentity) -> Result<(), String> {
            Ok(())
        }
        fn terminate_process(&self, _: &ProcessIdentity, _: bool) -> Result<(), String> {
            Ok(())
        }
        fn add_wfp_app_rule(&self, _: &Path, _: Option<IpAddr>, _: bool) -> Result<u64, String> {
            let h = self.next_handle.fetch_add(1, Ordering::Relaxed);
            self.active.lock().unwrap().insert(h);
            Ok(h)
        }
        fn remove_wfp_rule(&self, handle: u64) -> Result<(), String> {
            self.active.lock().unwrap().remove(&handle);
            Ok(())
        }
    }

    let defense = Arc::new(HandleTrackingDefense::new());
    let store = LedrStore::open_in_memory().expect("in-memory store");
    let engine = DaemonEngine::start_with_all_dependencies(
        store,
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::Enforce,
            ..DaemonConfig::default()
        },
        Arc::clone(&defense) as Arc<dyn ActiveDefenseController>,
        Arc::new(StubNotifier),
        Arc::new(FixedShaInspector("d".repeat(64))),
        Arc::new(MapLiveProcessInspector::new([])),
    );
    // Shrink primary process table capacity to 2 so `A.exe` is deterministically displaced into
    // `evicted_live` while still running.
    {
        let mut table = engine
            .process_table
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *table = ActiveProcessTable::new(2);
    }
    let sender = engine.sender();
    let now_ms = current_unix_ms();
    let base_100ns = 116_444_736_000_000_000u64 + ((now_ms - 5_000) as u64) * 10_000;

    async fn send_and_wait(engine: &DaemonEngine, sender: &TwoLaneSender, ev: SensorEvent) {
        let hp = engine.high_priority_processed.load(Ordering::Relaxed);
        sender.send(ev).await.expect("send sensor event");
        let dl = tokio::time::Instant::now() + Duration::from_secs(5);
        while engine.high_priority_processed.load(Ordering::Relaxed) < hp + 1 {
            assert!(tokio::time::Instant::now() < dl, "event processed");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    // --- Part 1: Unbound late-MOTW evicted-live process superseded by PID reuse ---
    let exe_a = r"C:\Program Files\NormalApp\late_motw_reused_a.exe";
    let exe_b = r"C:\Program Files\OtherApp\pid_reuser_b.exe";
    let pid_a = ProcessIdentity::new(9701, base_100ns);
    send_and_wait(
        &engine,
        &sender,
        SensorEvent::ProcessStart {
            identity: pid_a,
            parent_pid: 4,
            exe_path: exe_a.to_string(),
            command_line: "a.exe".to_string(),
            user_sid: None,
        },
    )
    .await;
    assert!(
        !try_has_active_wfp_filter(&engine, exe_a, None, false, Duration::from_secs(2))
            .await
            .expect("firewall lock"),
        "normal-folder app without MOTW must not have Preemptive block yet"
    );

    // Evict A from primary `entries` into `evicted_live`.
    for (i, pid) in [9702u32, 9703u32].into_iter().enumerate() {
        send_and_wait(
            &engine,
            &sender,
            SensorEvent::ProcessStart {
                identity: ProcessIdentity::new(pid, base_100ns + ((i + 1) as u64) * 10_000),
                parent_pid: 4,
                exe_path: format!(r"C:\Program Files\Pad\pad_{pid}.exe"),
                command_line: format!("pad_{pid}.exe"),
                user_sid: None,
            },
        )
        .await;
    }
    {
        let table = engine
            .process_table
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        assert!(table.get_by_instance_id(&pid_a.instance_id()).is_none());
        assert!(table.has_active_exe_key(&WfpRuleManager::exe_key(exe_a)));
    }

    // Delayed MOTW arrives for evicted-live A -> installs Preemptive WFP block.
    engine.apply_late_motw_attribution(LateMotwAttribution {
        instance_ids: vec![pid_a.instance_id()],
        attribution: MotwAttribution {
            origin_url: "https://dl.example.test/late_motw_reused_a.exe".to_string(),
            referrer_url: None,
            frame_url: None,
            sha256: Some("d".repeat(64)),
            stage: MotwMatchStage::ZoneIdentifierAds,
            zone_id: Some(3),
        },
    });
    assert!(
        try_has_active_wfp_filter(&engine, exe_a, None, false, Duration::from_secs(2))
            .await
            .expect("firewall lock"),
        "delayed MOTW attribution must install Preemptive WFP block for evicted-live A"
    );

    // Successor B reuses PID 9701 BEFORE A's ProcessStop arrives -> must clean up A's block!
    let pid_b = ProcessIdentity::new(9701, base_100ns + 50_000);
    send_and_wait(
        &engine,
        &sender,
        SensorEvent::ProcessStart {
            identity: pid_b,
            parent_pid: 4,
            exe_path: exe_b.to_string(),
            command_line: "b.exe".to_string(),
            user_sid: None,
        },
    )
    .await;
    assert!(
        !try_has_active_wfp_filter(&engine, exe_a, None, false, Duration::from_secs(2))
            .await
            .expect("firewall lock"),
        "PID reuse superseding evicted-live A must remove A's unused Preemptive WFP block"
    );
    assert!(
        defense.active_handles().is_empty(),
        "zero OS BFE handles may remain after superseded A's Preemptive block is removed"
    );

    // Late-arriving ProcessStop for A (earlier timestamp than B) must be a harmless no-op on B.
    send_and_wait(
        &engine,
        &sender,
        SensorEvent::ProcessStop {
            pid: 9701,
            exit_time_100ns: base_100ns + 40_000,
            exit_code: 0,
        },
    )
    .await;
    {
        let table = engine
            .process_table
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        assert!(
            table.has_active_exe_key(&WfpRuleManager::exe_key(exe_b)),
            "late ProcessStop for old A must not mark reused successor B as exited"
        );
    }

    // --- Part 2: Alert-bound evicted-live process superseded by PID reuse marks deferred ---
    let exe_bound = r"C:\Program Files\NormalApp\late_motw_bound_a2.exe";
    let pid_bound = ProcessIdentity::new(9710, base_100ns + 100_000);
    send_and_wait(
        &engine,
        &sender,
        SensorEvent::ProcessStart {
            identity: pid_bound,
            parent_pid: 4,
            exe_path: exe_bound.to_string(),
            command_line: "a2.exe".to_string(),
            user_sid: None,
        },
    )
    .await;
    for (i, pid) in [9711u32, 9712u32].into_iter().enumerate() {
        send_and_wait(
            &engine,
            &sender,
            SensorEvent::ProcessStart {
                identity: ProcessIdentity::new(pid, base_100ns + 110_000 + (i as u64) * 10_000),
                parent_pid: 4,
                exe_path: format!(r"C:\Program Files\Pad\pad2_{pid}.exe"),
                command_line: format!("pad2_{pid}.exe"),
                user_sid: None,
            },
        )
        .await;
    }
    engine.apply_late_motw_attribution(LateMotwAttribution {
        instance_ids: vec![pid_bound.instance_id()],
        attribution: MotwAttribution {
            origin_url: "https://dl.example.test/late_motw_bound_a2.exe".to_string(),
            referrer_url: None,
            frame_url: None,
            sha256: Some("d".repeat(64)),
            stage: MotwMatchStage::ZoneIdentifierAds,
            zone_id: Some(3),
        },
    });
    let alert_bound = AlertRecord {
        alert_id: "ALT-PREEMPT-REUSE-BOUND".to_string(),
        timestamp_ms: now_ms,
        severity: AlertSeverity::High,
        source_layer: "LAYER_3_NETWORK".to_string(),
        rule_id: "WFP-PREEMPT-REUSE".to_string(),
        title: "Alert bound to late-MOTW evicted exe".to_string(),
        process_instance_id: Some(pid_bound.instance_id()),
        process_suspended: false,
        status: AlertStatus::Pending,
        context_json: serde_json::json!({ "exe_path": exe_bound }).to_string(),
        resolved_at_ms: None,
    };
    engine.store.record_alert(&alert_bound).expect("record alert");
    {
        let mut fw = engine.firewall.lock().unwrap_or_else(|e| e.into_inner());
        assert!(fw.bind_alert_to_app_block(&alert_bound.alert_id, exe_bound));
    }

    // PID 9710 reused by B2 -> Preemptive block stays active while alert is bound, and is marked deferred.
    send_and_wait(
        &engine,
        &sender,
        SensorEvent::ProcessStart {
            identity: ProcessIdentity::new(9710, base_100ns + 200_000),
            parent_pid: 4,
            exe_path: r"C:\Program Files\OtherApp\reuser_b2.exe".to_string(),
            command_line: "b2.exe".to_string(),
            user_sid: None,
        },
    )
    .await;
    {
        let fw = engine.firewall.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            fw.has_active_filter(exe_bound, None, false),
            "bound alert must keep Preemptive block active across PID reuse"
        );
        assert!(
            fw.has_deferred_preemptive_removal(exe_bound),
            "PID reuse cleanup must mark deferred_preemptive_removals when an alert is bound"
        );
    }
    // Resolving the alert removes the deferred Preemptive block cleanly.
    engine
        .resolve_alert(
            &alert_bound.alert_id,
            ledr_proto::AlertDecision::TerminateAndBlock {
                add_block_rule: false,
            },
        )
        .expect("resolve alert");
    assert!(
        !try_has_active_wfp_filter(&engine, exe_bound, None, false, Duration::from_secs(2))
            .await
            .expect("firewall lock"),
        "resolving final bound alert after PID reuse must remove deferred Preemptive block"
    );

    // --- Part 3: Sibling instance of the same executable keeps Preemptive block intact ---
    let exe_sib = r"C:\Program Files\NormalApp\late_motw_sib_a3.exe";
    let pid_sib1 = ProcessIdentity::new(9720, base_100ns + 300_000);
    let pid_sib2 = ProcessIdentity::new(9721, base_100ns + 310_000);
    send_and_wait(
        &engine,
        &sender,
        SensorEvent::ProcessStart {
            identity: pid_sib1,
            parent_pid: 4,
            exe_path: exe_sib.to_string(),
            command_line: "a3_1.exe".to_string(),
            user_sid: None,
        },
    )
    .await;
    send_and_wait(
        &engine,
        &sender,
        SensorEvent::ProcessStart {
            identity: pid_sib2,
            parent_pid: 4,
            exe_path: exe_sib.to_string(),
            command_line: "a3_2.exe".to_string(),
            user_sid: None,
        },
    )
    .await;
    for (i, pid) in [9722u32, 9723u32].into_iter().enumerate() {
        send_and_wait(
            &engine,
            &sender,
            SensorEvent::ProcessStart {
                identity: ProcessIdentity::new(pid, base_100ns + 320_000 + (i as u64) * 10_000),
                parent_pid: 4,
                exe_path: format!(r"C:\Program Files\Pad\pad3_{pid}.exe"),
                command_line: format!("pad3_{pid}.exe"),
                user_sid: None,
            },
        )
        .await;
    }
    engine.apply_late_motw_attribution(LateMotwAttribution {
        instance_ids: vec![pid_sib1.instance_id(), pid_sib2.instance_id()],
        attribution: MotwAttribution {
            origin_url: "https://dl.example.test/late_motw_sib_a3.exe".to_string(),
            referrer_url: None,
            frame_url: None,
            sha256: Some("d".repeat(64)),
            stage: MotwMatchStage::ZoneIdentifierAds,
            zone_id: Some(3),
        },
    });
    // Reuse PID 9720 only -> sibling 9721 is still live, so Preemptive block must stay!
    send_and_wait(
        &engine,
        &sender,
        SensorEvent::ProcessStart {
            identity: ProcessIdentity::new(9720, base_100ns + 400_000),
            parent_pid: 4,
            exe_path: r"C:\Program Files\OtherApp\reuser_b3.exe".to_string(),
            command_line: "b3.exe".to_string(),
            user_sid: None,
        },
    )
    .await;
    assert!(
        try_has_active_wfp_filter(&engine, exe_sib, None, false, Duration::from_secs(2))
            .await
            .expect("firewall lock"),
        "running sibling must keep Preemptive block active when only one instance's PID is reused"
    );

    engine.shutdown_and_flush().await.expect("shutdown engine");
}

/// `PROC-MEM-01` (Engine Integration): Verifies `DaemonEngine::run_periodic_memory_maintenance`
/// respects `firewall -> process_table -> path_interner` lock order (`try_lock`), shrinks idle
/// `TelemetryRing`, compacts >60s exited entries without touching active/recent entries, and is
/// suppressed when `store.is_shutdown_requested()` is true.
#[tokio::test]
async fn proc_mem_01_engine_maintenance_and_shutdown_guard() {
    let store = LedrStore::open_in_memory().expect("open store");
    let engine = DaemonEngine::start_with_all_dependencies(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig::default(),
        Arc::new(RecordingDefense::new()),
        Arc::new(StubNotifier),
        Arc::new(FixedShaInspector("d".repeat(64))),
        Arc::new(MapLiveProcessInspector::new([])),
    );

    let now_ms = super::super::current_unix_ms();
    let old_id = ProcessIdentity::new(7101, 10_000);
    let recent_id = ProcessIdentity::new(7102, 20_000);
    {
        let mut table = engine
            .process_table
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        table.on_process_start(
            old_id,
            4,
            r"C:\Tools\old_mem.exe".to_string(),
            "old_mem.exe --keep".to_string(),
            Some("S-1-5-21-7101".to_string()),
            now_ms - 120_000,
        );
        table.set_motw_metadata(
            &old_id.instance_id(),
            "https://dl.example/old.exe".to_string(),
            "Zone.Identifier".to_string(),
            Some("https://ref.example/old".to_string()),
            Some("https://frame.example/old".to_string()),
            Some(3),
        );
        assert_eq!(
            table.on_process_stop(old_id.pid, now_ms - 90_000),
            Some(old_id.instance_id())
        );

        table.on_process_start(
            recent_id,
            4,
            r"C:\Tools\recent_mem.exe".to_string(),
            "recent_mem.exe".to_string(),
            Some("S-1-5-21-7102".to_string()),
            now_ms - 15_000,
        );
        table.set_motw_metadata(
            &recent_id.instance_id(),
            "https://dl.example/recent.exe".to_string(),
            "Zone.Identifier".to_string(),
            Some("https://ref.example/recent".to_string()),
            None,
            Some(3),
        );
        assert_eq!(
            table.on_process_stop(recent_id.pid, now_ms - 10_000),
            Some(recent_id.instance_id())
        );
    }

    // Verify strict leaf lock order `firewall -> process_table -> path_interner` via `try_lock`.
    {
        let _fw = engine.firewall.try_lock().expect("firewall try_lock");
        let table = engine
            .process_table
            .try_lock()
            .expect("process_table try_lock under firewall");
        let interner = table.path_interner();
        let _interner_guard = interner
            .try_lock()
            .expect("path_interner leaf try_lock under process_table");
    }

    engine.run_periodic_memory_maintenance();

    {
        let table = engine
            .process_table
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let old = table
            .get_by_instance_id(&old_id.instance_id())
            .expect("old exited entry must stay in entries");
        assert_eq!(old.user_sid, None);
        assert_eq!(old.motw_referrer, None);
        assert_eq!(old.motw_frame_url, None);
        assert_eq!(old.motw_source, None);
        assert_eq!(old.motw_zone_id, None);
        assert_eq!(old.origin_url.as_deref(), Some("https://dl.example/old.exe"));
        assert_eq!(old.command_line, "old_mem.exe --keep");

        let recent = table
            .get_by_instance_id(&recent_id.instance_id())
            .expect("recent exited entry");
        assert_eq!(recent.user_sid.as_deref(), Some("S-1-5-21-7102"));
        assert_eq!(recent.motw_zone_id, Some(3));
    }

    // Once shutdown is requested, periodic maintenance must be suppressed.
    store.request_shutdown();
    {
        let mut table = engine
            .process_table
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let suppressed_id = ProcessIdentity::new(7103, 30_000);
        table.on_process_start(
            suppressed_id,
            4,
            r"C:\Tools\suppressed.exe".to_string(),
            "suppressed.exe".to_string(),
            Some("S-1-5-21-7103".to_string()),
            now_ms - 120_000,
        );
        table.on_process_stop(suppressed_id.pid, now_ms - 90_000);
    }
    engine.run_periodic_memory_maintenance();
    {
        let table = engine
            .process_table
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let suppressed = table
            .get_by_instance_id("7103:30000")
            .expect("suppressed entry present");
        assert_eq!(
            suppressed.user_sid.as_deref(),
            Some("S-1-5-21-7103"),
            "maintenance must be skipped once store.is_shutdown_requested() is true"
        );
    }

    store.clear_shutdown_flag();
    engine.shutdown_and_flush().await.expect("shutdown engine");
}

/// `MEM-MAINT-BURST-01`: Periodic memory maintenance executes in Tier 2c-mem under continuous
/// Tier 3 telemetry backlog instead of starving in `tokio::select!`, and is suppressed once
/// `store.is_shutdown_requested()` becomes true (`PRRT_kwDOVyjVyM66vYBQ`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mem_maint_burst_01_runs_under_telemetry_backlog_and_stops_on_shutdown() {
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;
    let store = LedrStore::open_in_memory().expect("open store");
    let engine = DaemonEngine::start_with_all_dependencies(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig::default(),
        Arc::new(RecordingDefense::new()),
        Arc::new(StubNotifier),
        Arc::new(FixedShaInspector("e".repeat(64))),
        Arc::new(MapLiveProcessInspector::new([])),
    );
    engine.set_mem_maintenance_interval_for_test(Duration::from_millis(20));

    let now_ms = super::super::current_unix_ms();
    let old_id = ProcessIdentity::new(7201, 10_000);
    {
        let mut table = engine
            .process_table
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        table.on_process_start(
            old_id,
            4,
            r"C:\Tools\burst_mem.exe".to_string(),
            "burst_mem.exe".to_string(),
            Some("S-1-5-21-mem-burst".to_string()),
            now_ms - 120_000,
        );
        table.on_process_stop(old_id.pid, now_ms - 90_000);
    }

    struct FloodGuard {
        stop: Arc<AtomicBool>,
        handle: Option<std::thread::JoinHandle<()>>,
    }
    impl FloodGuard {
        fn stop_and_join(&mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }
    impl Drop for FloodGuard {
        fn drop(&mut self) {
            self.stop_and_join();
        }
    }

    let sender = engine.sender();
    let stop_flood = Arc::new(AtomicBool::new(false));
    let stop_flood_bg = Arc::clone(&stop_flood);
    let flood_thread = std::thread::spawn(move || {
        let mut seq = 0u64;
        'flood: while !stop_flood_bg.load(Ordering::Acquire) {
            if sender.telemetry_depth() < 2048 {
                for _ in 0..64 {
                    if stop_flood_bg.load(Ordering::Acquire) {
                        break 'flood;
                    }
                    seq = seq.wrapping_add(1);
                    if sender
                        .send_telemetry(SensorEvent::DnsQuery {
                            pid: 4242,
                            query_name: format!("burst-{seq}.example.com"),
                            query_type: 1,
                            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
                            timestamp_ms: 1_700_000_000_000 + (seq as i64),
                        })
                        .is_err()
                    {
                        break 'flood;
                    }
                }
            } else {
                std::thread::yield_now();
            }
        }
    });
    let mut flood_guard = FloodGuard {
        stop: stop_flood,
        handle: Some(flood_thread),
    };

    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while engine.tier2c_mem_maintenance_runs.load(Ordering::Acquire) == 0
        || engine.telemetry_processed.load(Ordering::Acquire) == 0
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "Tier 2c-mem maintenance must execute even under continuous Tier 3 telemetry backlog"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert_eq!(
        engine.select_idle_mem_maintenance_runs.load(Ordering::Acquire),
        0,
        "idle select! maintenance branch must not have run while telemetry was continuously flooded"
    );
    {
        let table = engine
            .process_table
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let old = table
            .get_by_instance_id(&old_id.instance_id())
            .expect("old exited entry present");
        assert_eq!(
            old.user_sid, None,
            "Tier 2c-mem maintenance must have compacted stale non-lineage metadata under flood"
        );
    }

    // Request shutdown and verify maintenance stops immediately even as interval elapses.
    store.request_shutdown();
    let runs_at_shutdown = engine.tier2c_mem_maintenance_runs.load(Ordering::Acquire);
    let suppressed_id = ProcessIdentity::new(7202, 20_000);
    {
        let mut table = engine
            .process_table
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        table.on_process_start(
            suppressed_id,
            4,
            r"C:\Tools\burst_suppressed.exe".to_string(),
            "burst_suppressed.exe".to_string(),
            Some("S-1-5-21-mem-suppressed".to_string()),
            now_ms - 120_000,
        );
        table.on_process_stop(suppressed_id.pid, now_ms - 90_000);
    }

    tokio::time::sleep(Duration::from_millis(60)).await;
    assert_eq!(
        engine.tier2c_mem_maintenance_runs.load(Ordering::Acquire),
        runs_at_shutdown,
        "Tier 2c-mem maintenance must be suppressed after store.request_shutdown()"
    );
    {
        let table = engine
            .process_table
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let suppressed = table
            .get_by_instance_id(&suppressed_id.instance_id())
            .expect("suppressed entry present");
        assert_eq!(
            suppressed.user_sid.as_deref(),
            Some("S-1-5-21-mem-suppressed")
        );
    }

    flood_guard.stop_and_join();
    store.clear_shutdown_flag();
    engine.shutdown_and_flush().await.expect("shutdown engine");
}
