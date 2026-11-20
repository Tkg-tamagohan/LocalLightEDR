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
    let script_id = ProcessIdentity::new(42001, 2001);
    let unknown_id = ProcessIdentity::new(42002, 2002);

    send_process_start(
        &engine,
        script_id,
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    );
    send_process_start(&engine, unknown_id, r"C:\Apps\unknown.exe");

    // DNS resolution for a domain-scoped NetworkBlock must not pre-materialize WFP filters in Audit mode.
    let _ = engine.process_event_with_lane(
        &SensorEvent::DnsQuery {
            pid: unknown_id.pid,
            query_name: "c2.audit-blocked.example".to_string(),
            query_type: 1,
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 89))],
            timestamp_ms: now_ms,
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
                timestamp_ms: now_ms,
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
            },
        ),
        (
            7704,
            ledr_sensor_win::etw::LiveProcessInfo {
                create_time_100ns: live_create_100ns,
                exe_path: Some("   ".to_string()),
                command_line: None,
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
            },
        ),
        (
            4404,
            ledr_sensor_win::etw::LiveProcessInfo {
                create_time_100ns: created_100ns,
                exe_path: Some(r"C:\Temp\zero_ts_upgraded.exe".to_string()),
                command_line: None,
            },
        ),
        (
            4408,
            ledr_sensor_win::etw::LiveProcessInfo {
                create_time_100ns: created_100ns,
                exe_path: None,
                command_line: None,
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
    let _ = engine.process_event_with_lane(
        &SensorEvent::CanaryFileAccess {
            pid: 4404,
            target_path: r"C:\Users\alice\.aws\credentials".to_string(),
            category: CanaryCategory::CloudCredential,
            access_mask: 1,
            is_write_or_delete: false,
            timestamp_ms: now_ms + 50,
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
    let _ = engine.process_event_with_lane(
        &SensorEvent::CanaryFileAccess {
            pid: 4408,
            target_path: r"C:\Users\alice\.env.noop".to_string(),
            category: CanaryCategory::EnvFile,
            access_mask: 1,
            is_write_or_delete: false,
            timestamp_ms: now_ms + 100,
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
        },
    );
    let _ = engine.process_event_with_lane(
        &SensorEvent::CanaryFileAccess {
            pid: 4408,
            target_path: r"C:\Users\alice\.env.enriched".to_string(),
            category: CanaryCategory::EnvFile,
            access_mask: 1,
            is_write_or_delete: false,
            timestamp_ms: now_ms + 200,
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
