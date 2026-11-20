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
                elapsed < Duration::from_secs(2),
                "ANALYSIS_0003: shutdown must complete within budget even with wedged NRD (took {elapsed:?})"
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
