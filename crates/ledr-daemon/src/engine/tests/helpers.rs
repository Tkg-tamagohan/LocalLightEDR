use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use ledr_proto::{
    ActiveDefenseController, AlertRecord, AlertSeverity, AlertStatus, AllowlistRuleRecord,
    ProcessIdentity, RuleScope, SensorEvent,
};
use ledr_rules::{BinaryIdentity, EarlyPruner, SigmaEngine};
use ledr_store::LedrStore;

use crate::engine::events::DnsCorrelationUpdate;
use crate::firewall::{WfpFilterOrigin, WfpRuleManager};

use super::{
    BinaryInspector, DaemonConfig, DaemonEngine, EventLane, NotificationDispatcher, QueuedWfpDrop,
};

pub(super) struct TestDefense {
    next_handle: AtomicU64,
    suspends: AtomicUsize,
    fail_removes: AtomicBool,
}

impl TestDefense {
    pub(super) fn new(start_handle: u64) -> Self {
        Self {
            next_handle: AtomicU64::new(start_handle),
            suspends: AtomicUsize::new(0),
            fail_removes: AtomicBool::new(false),
        }
    }

    pub(super) fn suspends(&self) -> usize {
        self.suspends.load(Ordering::Relaxed)
    }

    pub(super) fn set_fail_removes(&self, fail: bool) {
        self.fail_removes.store(fail, Ordering::Release);
    }
}

impl ActiveDefenseController for TestDefense {
    fn suspend_process(&self, _: &ProcessIdentity, _: bool) -> Result<(), String> {
        self.suspends.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    fn resume_process(&self, _: &ProcessIdentity) -> Result<(), String> {
        Ok(())
    }
    fn terminate_process(&self, _: &ProcessIdentity, _: bool) -> Result<(), String> {
        Ok(())
    }
    fn add_wfp_app_rule(&self, _: &Path, _: Option<IpAddr>, _: bool) -> Result<u64, String> {
        Ok(self.next_handle.fetch_add(1, Ordering::Relaxed))
    }
    fn remove_wfp_rule(&self, filter_id: u64) -> Result<(), String> {
        if self.fail_removes.load(Ordering::Acquire) {
            return Err(format!("mock remove failure for handle {filter_id}"));
        }
        Ok(())
    }
}

pub(super) struct StubNotifier;

impl NotificationDispatcher for StubNotifier {
    fn notify_alert(&self, _: &AlertRecord) -> Result<(), String> {
        Ok(())
    }
}

pub(super) struct FixedShaInspector(pub(super) String);

impl BinaryInspector for FixedShaInspector {
    fn inspect(&self, exe_path: &str) -> BinaryIdentity {
        BinaryIdentity {
            exe_path: exe_path.to_string(),
            sha256: Some(self.0.clone()),
            authenticode: None,
        }
    }
}

pub(super) async fn start_stopped_engine(
    store: LedrStore,
    config: DaemonConfig,
    defense: Arc<dyn ActiveDefenseController>,
    inspector: Arc<dyn BinaryInspector>,
) -> Arc<DaemonEngine> {
    let engine = DaemonEngine::start_with_dependencies(
        store,
        SigmaEngine::default(),
        EarlyPruner::default(),
        config,
        defense,
        Arc::new(StubNotifier),
        inspector,
    );
    if let Some(h) = engine.worker_handle.lock().await.take() {
        h.abort();
        let _ = h.await;
    }
    engine
}

pub(super) fn send_process_start(
    engine: &DaemonEngine,
    identity: ProcessIdentity,
    exe_path: &str,
) {
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStart {
            identity,
            parent_pid: 4,
            exe_path: exe_path.to_string(),
            command_line: exe_path.to_string(),
            user_sid: None,
        },
        EventLane::HighPriority,
    );
}

pub(super) fn send_process_stop(engine: &DaemonEngine, pid: u32, exit_time_100ns: u64) {
    let _ = engine.process_event_with_lane(
        &SensorEvent::ProcessStop {
            pid,
            exit_time_100ns,
            exit_code: 0,
        },
        EventLane::HighPriority,
    );
}

pub(super) fn send_dns_typed(
    engine: &DaemonEngine,
    pid: u32,
    query_name: &str,
    query_type: u16,
    resolved_ips: &[IpAddr],
    timestamp_ms: i64,
) -> Option<DnsCorrelationUpdate> {
    engine.process_event_with_lane(
        &SensorEvent::DnsQuery {
            pid,
            query_name: query_name.to_string(),
            query_type,
            resolved_ips: resolved_ips.to_vec(),
            timestamp_ms,
        },
        EventLane::HighPriority,
    )
}

pub(super) fn send_dns(
    engine: &DaemonEngine,
    pid: u32,
    query_name: &str,
    resolved_ips: &[IpAddr],
    timestamp_ms: i64,
) -> Option<DnsCorrelationUpdate> {
    send_dns_typed(engine, pid, query_name, 1, resolved_ips, timestamp_ms)
}

pub(super) fn send_connect(
    engine: &DaemonEngine,
    pid: u32,
    dst_ip: IpAddr,
    domain_hint: Option<&str>,
    timestamp_ms: i64,
) {
    let _ = engine.process_event_with_lane(
        &SensorEvent::NetworkConnect {
            pid,
            protocol: 6,
            dst_ip,
            dst_port: 443,
            domain_hint: domain_hint.map(str::to_string),
            timestamp_ms,
        },
        EventLane::HighPriority,
    );
}

pub(super) fn make_net_rule(
    rule_id: &str,
    scope: RuleScope,
    exe_path: &str,
    sha256: &str,
    allowed_target: &str,
    created_at_ms: i64,
) -> AllowlistRuleRecord {
    AllowlistRuleRecord {
        rule_id: rule_id.to_string(),
        scope,
        exe_path_pattern: exe_path.to_string(),
        sha256: Some(sha256.to_string()),
        signer_subject: None,
        root_thumbprint: None,
        allowed_target: Some(allowed_target.to_string()),
        created_at_ms,
        created_by: "test".to_string(),
    }
}

pub(super) fn make_pending_net_alert(
    alert_id: &str,
    timestamp_ms: i64,
    rule_id: &str,
    title: &str,
    process_instance_id: Option<String>,
    context_json: serde_json::Value,
) -> AlertRecord {
    AlertRecord {
        alert_id: alert_id.to_string(),
        timestamp_ms,
        severity: AlertSeverity::High,
        source_layer: "LAYER_3_NETWORK".to_string(),
        rule_id: rule_id.to_string(),
        title: title.to_string(),
        process_instance_id,
        process_suspended: false,
        status: AlertStatus::Pending,
        context_json: context_json.to_string(),
        resolved_at_ms: None,
    }
}

pub(super) fn make_queued_drop(
    exe_path: &str,
    dst_ip: IpAddr,
    timestamp_ms: i64,
    os_filter_id: u64,
) -> QueuedWfpDrop {
    QueuedWfpDrop {
        exe_path: exe_path.to_string(),
        exe_key: WfpRuleManager::exe_key(exe_path),
        dst_ip,
        dst_port: 443,
        protocol: 6,
        timestamp_ms,
        os_filter_id,
    }
}

#[track_caller]
pub(super) fn assert_domain_policy_hints(
    engine: &DaemonEngine,
    exe_path: &str,
    ip: IpAddr,
    expected: &[&str],
    msg: &str,
) {
    let expected_origin = WfpFilterOrigin::DomainPolicy {
        domain_hints: expected.iter().map(|s| (*s).to_string()).collect(),
    };
    let actual = engine.firewall.lock().unwrap().filter_origin(exe_path, Some(ip)).cloned();
    if msg.is_empty() {
        assert_eq!(actual, Some(expected_origin));
    } else {
        assert_eq!(actual, Some(expected_origin), "{msg}");
    }
}
