use super::ProcessDnsHistory;
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn process_dns_history_is_bounded_and_scoped_by_instance() {
    let mut hist = ProcessDnsHistory::new(2);
    let ip1 = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    let ip2 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
    let ip3 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 20));

    hist.record("100:1", "Allowed.Example.", &[ip1], 1_000);
    hist.record("200:2", "Other.Example", &[ip2], 1_100);
    assert!(hist.another_process_resolved(Some("300:3"), "allowed.example", ip1, 1_200));
    assert!(!hist.another_process_resolved(Some("100:1"), "allowed.example", ip1, 1_200));

    hist.record("300:3", "Third.Example", &[ip3], 1_300);
    assert_eq!(hist.entries.len(), 2);
    assert!(hist.lookup_for_process("100:1", ip1).is_none());

    hist.remove_process("200:2");
    assert!(hist.lookup_for_process("200:2", ip2).is_none());
    assert_eq!(hist.entries.len(), 1);
}

#[test]
fn process_dns_history_invalidates_retired_ipv4_preserves_v6_and_enforces_freshness() {
    use std::net::Ipv6Addr;

    let mut hist = ProcessDnsHistory::new(16);
    let v4_old = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
    let v4_new = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 20));
    let v6_a = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

    hist.record_for_exe("10:1", r"c:\tools\app.exe", "Evil.Example.", &[v4_old], 1_000);
    hist.record_for_exe("10:1", r"c:\tools\app.exe", "Evil.Example.", &[v6_a], 1_010);
    assert!(
        hist.lookup_for_process("10:1", v4_old).is_some(),
        "AAAA query must not erase active IPv4 mapping"
    );
    assert!(hist.lookup_for_process("10:1", v6_a).is_some());

    // Rotating IPv4 via a sibling instance of the same executable invalidates `v4_old` across
    // instances while leaving `v6_a` and unrelated executables intact.
    hist.record_for_exe("30:1", r"c:\tools\other.exe", "Evil.Example.", &[v4_old], 1_020);
    hist.record_for_exe("20:1", r"c:\tools\app.exe", "Evil.Example.", &[v4_new], 2_000);
    assert!(hist.lookup_for_process("10:1", v4_old).is_none());
    assert!(hist.lookup_for_process("20:1", v4_new).is_some());
    assert!(hist.lookup_for_process("10:1", v6_a).is_some());
    assert!(hist.lookup_for_process("30:1", v4_old).is_some());

    // Freshness check obeys `max_age_ms` and exe scoping.
    assert!(hist
        .lookup_fresh_for_process("20:1", v4_new, 62_000, 60_000)
        .is_some());
    assert!(hist
        .lookup_fresh_for_process("20:1", v4_new, 62_001, 60_000)
        .is_none());
    assert_eq!(
        hist.domains_for_exe_ip(r"c:\tools\app.exe", v4_new),
        vec!["evil.example".to_string()]
    );
    assert!(hist
        .domains_for_exe_ip(r"c:\tools\other.exe", v4_new)
        .is_empty());
}

/// `DAEMON-P3-43A` (`R-07`): Dual-stack DNS history tracks latest IP sets and timestamps
/// independently per address family (IPv4 vs IPv6), handles mixed queries without cross-family
/// interference, and never regresses existing `entries` timestamps on delayed responses.
#[test]
fn daemon_p3_43a_dual_stack_dns_family_independent_timestamps_and_non_regression() {
    use std::net::Ipv6Addr;

    let mut hist = ProcessDnsHistory::new(32);
    let exe = r"c:\tools\dualstack.exe";
    let v4_1 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
    let v4_2 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20));
    let v4_3 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 30));
    let v4_stale = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99));
    let v6_1 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    let v6_2 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));
    let v6_stale = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 99));

    // 1. A(1000) -> AAAA(3000) -> A(2000): IPv4 is newer than prior IPv4 (2000 >= 1000)
    //    so it must be accepted even though AAAA has a newer timestamp (3000).
    assert_eq!(
        hist.record_for_exe("10:1", exe, "api.example.", &[v4_1], 1_000),
        vec![v4_1]
    );
    assert_eq!(
        hist.record_for_exe("10:1", exe, "api.example.", &[v6_1], 3_000),
        vec![v6_1]
    );
    assert_eq!(
        hist.record_for_exe("10:1", exe, "api.example.", &[v4_2], 2_000),
        vec![v4_2],
        "newer IPv4 response at t=2000 must not be rejected by AAAA at t=3000"
    );
    assert!(hist.lookup_for_process("10:1", v4_1).is_none());
    assert_eq!(
        hist.lookup_for_process("10:1", v4_2),
        Some(("api.example".to_string(), 2_000))
    );
    assert_eq!(
        hist.lookup_for_process("10:1", v6_1),
        Some(("api.example".to_string(), 3_000))
    );
    assert!(hist.is_domain_ip_superseded(exe, "api.example", v4_1));
    assert!(!hist.is_domain_ip_superseded(exe, "api.example", v4_2));
    assert!(!hist.is_domain_ip_superseded(exe, "api.example", v6_1));
    // IPv4-mapped IPv6 address must map to the IPv4 family for superseding checks.
    let v4_1_mapped = IpAddr::V6(Ipv4Addr::new(198, 51, 100, 10).to_ipv6_mapped());
    let v4_2_mapped = IpAddr::V6(Ipv4Addr::new(198, 51, 100, 20).to_ipv6_mapped());
    assert!(hist.is_domain_ip_superseded(exe, "api.example", v4_1_mapped));
    assert!(!hist.is_domain_ip_superseded(exe, "api.example", v4_2_mapped));

    // 2. Reverse order: AAAA(1000) -> A(3000) -> AAAA(2000).
    assert_eq!(
        hist.record_for_exe("20:1", exe, "rev.example", &[v6_1], 1_000),
        vec![v6_1]
    );
    assert_eq!(
        hist.record_for_exe("20:1", exe, "rev.example", &[v4_1], 3_000),
        vec![v4_1]
    );
    assert_eq!(
        hist.record_for_exe("20:1", exe, "rev.example", &[v6_2], 2_000),
        vec![v6_2],
        "newer IPv6 response at t=2000 must not be rejected by A at t=3000"
    );
    assert!(hist.lookup_for_process("20:1", v6_1).is_none());
    assert_eq!(
        hist.lookup_for_process("20:1", v6_2),
        Some(("rev.example".to_string(), 2_000))
    );
    assert_eq!(
        hist.lookup_for_process("20:1", v4_1),
        Some(("rev.example".to_string(), 3_000))
    );
    assert!(hist.is_domain_ip_superseded(exe, "rev.example", v6_1));
    assert!(!hist.is_domain_ip_superseded(exe, "rev.example", v6_2));
    assert!(!hist.is_domain_ip_superseded(exe, "rev.example", v4_1));

    // 3. Mixed IPv4/IPv6 query where one family is fresh and the other is delayed.
    assert_eq!(
        hist.record_for_exe("30:1", exe, "mix.example", &[v4_1], 1_000),
        vec![v4_1]
    );
    assert_eq!(
        hist.record_for_exe("30:1", exe, "mix.example", &[v6_1, v6_2], 3_000),
        vec![v6_1, v6_2]
    );
    // Sibling instance holds a delayed record for `v6_2` at t=2100 (still in latest IPv6 set).
    assert_eq!(
        hist.record_for_exe("31:1", exe, "mix.example", &[v6_2], 2_100),
        vec![v6_2]
    );
    // Mixed query at t=2000: `v4_2` updates IPv4, `v6_stale` is rejected for IPv6.
    assert_eq!(
        hist.record_for_exe("30:1", exe, "mix.example", &[v4_2, v6_stale], 2_000),
        vec![v4_2]
    );
    assert!(hist.lookup_for_process("30:1", v4_1).is_none());
    assert_eq!(
        hist.lookup_for_process("30:1", v4_2),
        Some(("mix.example".to_string(), 2_000))
    );
    assert!(hist.lookup_for_process("30:1", v6_stale).is_none());
    assert_eq!(
        hist.lookup_for_process("30:1", v6_1),
        Some(("mix.example".to_string(), 3_000))
    );
    assert_eq!(
        hist.lookup_for_process("30:1", v6_2),
        Some(("mix.example".to_string(), 3_000))
    );

    // Mixed query at t=2500: `v4_3` updates IPv4, while delayed `v6_1` is in current IPv6 set.
    // IPv6 latest timestamp was NOT updated, so `v6_2` (even sibling at t=2100 <= 2500) must
    // NOT be evicted, and `30:1`'s `v6_1` timestamp must NOT regress from 3000 to 2500.
    assert_eq!(
        hist.record_for_exe("30:1", exe, "mix.example", &[v4_3, v6_1], 2_500),
        vec![v4_3, v6_1]
    );
    assert!(hist.lookup_for_process("30:1", v4_2).is_none());
    assert_eq!(
        hist.lookup_for_process("30:1", v4_3),
        Some(("mix.example".to_string(), 2_500))
    );
    assert_eq!(
        hist.lookup_for_process("30:1", v6_1),
        Some(("mix.example".to_string(), 3_000)),
        "delayed query returning current latest IP must not regress existing timestamp_ms"
    );
    assert_eq!(
        hist.lookup_for_process("30:1", v6_2),
        Some(("mix.example".to_string(), 3_000)),
        "non-updated family must not evict sibling IPs in latest set"
    );
    assert_eq!(
        hist.lookup_for_process("31:1", v6_2),
        Some(("mix.example".to_string(), 2_100)),
        "delayed query must not evict older sibling entry for a still-current IP"
    );

    // 4. Delayed single-family responses: stale IP rejected, current IP does not regress ts,
    //    and cross-domain delayed responses do not clobber newer non-superseded entries.
    assert!(hist
        .record_for_exe("30:1", exe, "mix.example", &[v4_stale], 2_400)
        .is_empty());
    assert_eq!(
        hist.record_for_exe("30:1", exe, "mix.example", &[v4_3], 2_200),
        vec![v4_3]
    );
    assert_eq!(
        hist.lookup_for_process("30:1", v4_3),
        Some(("mix.example".to_string(), 2_500))
    );
    // `is_entry_superseded` must consult only the entry IP's own address family.
    let v4_entry_old = super::DnsHistoryEntry {
        exe_key: exe.to_string(),
        domains: vec![super::DomainTimestamp {
            domain: "api.example".to_string(),
            timestamp_ms: 1_000,
        }],
    };
    let v4_entry_cur = super::DnsHistoryEntry {
        exe_key: exe.to_string(),
        domains: vec![super::DomainTimestamp {
            domain: "api.example".to_string(),
            timestamp_ms: 2_000,
        }],
    };
    let v6_entry_cur = super::DnsHistoryEntry {
        exe_key: exe.to_string(),
        domains: vec![super::DomainTimestamp {
            domain: "api.example".to_string(),
            timestamp_ms: 3_000,
        }],
    };
    assert!(hist.is_entry_superseded(&v4_entry_old, v4_1));
    assert!(!hist.is_entry_superseded(&v4_entry_cur, v4_2));
    assert!(!hist.is_entry_superseded(&v6_entry_cur, v6_1));

    // Cross-domain delayed response sharing the same IP must not clobber a newer mapping.
    assert_eq!(
        hist.record_for_exe("40:1", exe, "newer.example", &[v4_3], 6_000),
        vec![v4_3]
    );
    assert_eq!(
        hist.record_for_exe("40:1", exe, "older.example", &[v4_3], 4_000),
        vec![v4_3]
    );
    assert_eq!(
        hist.lookup_for_process("40:1", v4_3),
        Some(("newer.example".to_string(), 6_000)),
        "delayed cross-domain DNS on shared IP must not regress or clobber newer entry"
    );
}

/// `DAEMON-P3-43B` (`R-03` + `R-07` boundary): `process_event_with_lane` returns only accepted
/// DNS IPs, and `flush_ready_pending_wfp_drops` keeps single-candidate pending entries parked
/// whenever `ProcessDnsHistory::lookup_for_process` has no usable record for that instance.
#[test]
fn daemon_p3_43b_r03_accepted_ips_and_flush_ready_history_guard() {
    use super::{
        current_unix_ms, DaemonConfig, DaemonEngine, EventLane, PendingWfpDrop, QueuedWfpDrop,
        WfpRuleManager,
    };
    use ledr_proto::{ProcessIdentity, SensorEvent};
    use ledr_rules::{EarlyPruner, SigmaEngine};
    use ledr_store::LedrStore;
    use std::collections::VecDeque;
    use std::net::Ipv6Addr;
    use std::time::Duration;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build rt");

    rt.block_on(async {
        let store = LedrStore::open_in_memory().expect("open store");
        let engine = DaemonEngine::start(
            store,
            SigmaEngine::default(),
            EarlyPruner::default(),
            DaemonConfig {
                outbound_firewall_enabled: false,
                ..DaemonConfig::default()
            },
        );
        // Stop background worker so we exercise `process_event_with_lane` and
        // `flush_ready_pending_wfp_drops` deterministically on the current task.
        if let Some(h) = engine.worker_handle.lock().await.take() {
            h.abort();
            let _ = h.await;
        }

        let now_ms = current_unix_ms();
        let exe = r"C:\Tools\r03_boundary.exe";
        let exe_key = WfpRuleManager::exe_key(exe);
        let proc_id = ProcessIdentity::new(9401, (now_ms as u64 + 11_644_473_600_000) * 10_000);
        let inst_id = format!("{}:{}", proc_id.pid, proc_id.create_time_100ns);

        let _ = engine.process_event_with_lane(
            &SensorEvent::ProcessStart {
                identity: proc_id,
                parent_pid: 4,
                exe_path: exe.to_string(),
                command_line: exe.to_string(),
                user_sid: None,
            },
            EventLane::HighPriority,
        );

        let v4_new = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 20));
        let v4_stale = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
        let v6_new = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x42));

        let upd1 = engine
            .process_event_with_lane(
                &SensorEvent::DnsQuery {
                    pid: proc_id.pid,
                    query_name: "svc.example".to_string(),
                    query_type: 1,
                    resolved_ips: vec![v4_new],
                    timestamp_ms: now_ms + 200,
                },
                EventLane::HighPriority,
            )
            .expect("fresh v4 dns accepted");
        assert_eq!(upd1.instance_id, inst_id);
        assert_eq!(upd1.exe_key, exe_key);
        assert_eq!(upd1.accepted_ips, vec![v4_new]);

        // Stale v4-only DNS response must yield `None` (no accepted IPs).
        assert!(
            engine
                .process_event_with_lane(
                    &SensorEvent::DnsQuery {
                        pid: proc_id.pid,
                        query_name: "svc.example".to_string(),
                        query_type: 1,
                        resolved_ips: vec![v4_stale],
                        timestamp_ms: now_ms + 100,
                    },
                    EventLane::HighPriority,
                )
                .is_none(),
            "stale DNS response must return None and never wake pending WFP drops"
        );

        // Mixed query: stale v4 is dropped, fresh v6 is returned in `accepted_ips`.
        let upd_mixed = engine
            .process_event_with_lane(
                &SensorEvent::DnsQuery {
                    pid: proc_id.pid,
                    query_name: "svc.example".to_string(),
                    query_type: 28,
                    resolved_ips: vec![v4_stale, v6_new],
                    timestamp_ms: now_ms + 150,
                },
                EventLane::HighPriority,
            )
            .expect("mixed query must accept v6");
        assert_eq!(upd_mixed.accepted_ips, vec![v6_new]);

        // Even with `candidates.len() == 1`, `flush_ready_pending_wfp_drops` must keep a
        // pending entry parked when `lookup_for_process(dns_inst_id, dst_ip)` is `None`.
        let mut pending = VecDeque::new();
        let future_deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        pending.push_back(PendingWfpDrop {
            item: QueuedWfpDrop {
                exe_path: exe.to_string(),
                exe_key: exe_key.clone(),
                dst_ip: v4_stale,
                dst_port: 443,
                protocol: 6,
                timestamp_ms: now_ms + 250,
                os_filter_id: 1,
            },
            deadline: future_deadline,
        });
        engine.flush_ready_pending_wfp_drops(
            &inst_id,
            &exe_key,
            "svc.example",
            &[v4_stale],
            &mut pending,
        );
        assert_eq!(
            pending.len(),
            1,
            "single-candidate drop without usable DNS history must remain parked until deadline"
        );

        // Once the pending drop matches an IP present in `lookup_for_process`, it flushes.
        pending.clear();
        pending.push_back(PendingWfpDrop {
            item: QueuedWfpDrop {
                exe_path: exe.to_string(),
                exe_key: exe_key.clone(),
                dst_ip: v6_new,
                dst_port: 443,
                protocol: 6,
                timestamp_ms: now_ms + 250,
                os_filter_id: 2,
            },
            deadline: future_deadline,
        });
        engine.flush_ready_pending_wfp_drops(
            &inst_id,
            &exe_key,
            "svc.example",
            &upd_mixed.accepted_ips,
            &mut pending,
        );
        assert!(
            pending.is_empty(),
            "single-candidate drop with usable DNS history must flush immediately"
        );

        // Multi-instance (`candidates.len() > 1`) symmetry: when an existing sibling only has
        // DNS older than `AMBIGUOUS_DNS_HISTORY_MAX_AGE_MS`, `on_wfp_drop_dequeued` must still
        // park the drop during the grace window, and `flush_ready_pending_wfp_drops` must keep
        // it parked on stale-age DNS until a fresh allowed DNS arrives.
        struct StubDefense(std::sync::atomic::AtomicU64);
        impl ledr_proto::ActiveDefenseController for StubDefense {
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
                _: &std::path::Path,
                _: Option<IpAddr>,
                _: bool,
            ) -> Result<u64, String> {
                Ok(self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
            }
            fn remove_wfp_rule(&self, _: u64) -> Result<(), String> {
                Ok(())
            }
        }
        struct StubNotifier;
        impl super::NotificationDispatcher for StubNotifier {
            fn notify_alert(&self, _: &ledr_proto::AlertRecord) -> Result<(), String> {
                Ok(())
            }
        }
        struct FixedShaInspector(String);
        impl super::BinaryInspector for FixedShaInspector {
            fn inspect(&self, exe_path: &str) -> ledr_rules::BinaryIdentity {
                ledr_rules::BinaryIdentity {
                    exe_path: exe_path.to_string(),
                    sha256: Some(self.0.clone()),
                    authenticode: None,
                }
            }
        }

        let test_sha = "a".repeat(64);
        let allow_exe = r"C:\Temp\multi_r03.exe";
        let allow_exe_key = WfpRuleManager::exe_key(allow_exe);
        let allow_store = LedrStore::open_in_memory().expect("open allow store");
        allow_store
            .upsert_rule(&ledr_proto::AllowlistRuleRecord {
                rule_id: "R-MULTI-ALLOW".to_string(),
                scope: ledr_proto::RuleScope::NetworkAllow,
                exe_path_pattern: allow_exe.to_string(),
                sha256: Some(test_sha.clone()),
                signer_subject: None,
                root_thumbprint: None,
                allowed_target: Some("good.example".to_string()),
                created_at_ms: now_ms - 10_000,
                created_by: "test".to_string(),
            })
            .expect("seed allow rule");
        let multi_engine = DaemonEngine::start_with_dependencies(
            allow_store,
            SigmaEngine::default(),
            EarlyPruner::default(),
            DaemonConfig {
                outbound_firewall_enabled: true,
                wfp_drop_dns_grace_ms: 500,
                ..DaemonConfig::default()
            },
            std::sync::Arc::new(StubDefense(std::sync::atomic::AtomicU64::new(1))),
            std::sync::Arc::new(StubNotifier),
            std::sync::Arc::new(FixedShaInspector(test_sha.clone())),
        );
        if let Some(h) = multi_engine.worker_handle.lock().await.take() {
            h.abort();
            let _ = h.await;
        }
        let proc_start_ms = now_ms - super::AMBIGUOUS_DNS_HISTORY_MAX_AGE_MS - 20_000;
        let p_a =
            ProcessIdentity::new(9411, (proc_start_ms as u64 + 11_644_473_600_000) * 10_000);
        let p_b =
            ProcessIdentity::new(9412, (proc_start_ms as u64 + 11_644_473_600_000) * 10_000);
        for pid_id in [p_a, p_b] {
            let _ = multi_engine.process_event_with_lane(
                &SensorEvent::ProcessStart {
                    identity: pid_id,
                    parent_pid: 4,
                    exe_path: allow_exe.to_string(),
                    command_line: allow_exe.to_string(),
                    user_sid: None,
                },
                EventLane::HighPriority,
            );
        }
        let shared_dst = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77));
        // Seed stale DNS (> AMBIGUOUS_DNS_HISTORY_MAX_AGE_MS old) on sibling `p_a`.
        let stale_upd = multi_engine
            .process_event_with_lane(
                &SensorEvent::DnsQuery {
                    pid: p_a.pid,
                    query_name: "good.example".to_string(),
                    query_type: 1,
                    resolved_ips: vec![shared_dst],
                    timestamp_ms: now_ms - super::AMBIGUOUS_DNS_HISTORY_MAX_AGE_MS - 5_000,
                },
                EventLane::HighPriority,
            )
            .expect("stale-age dns accepted as initial");
        let mut multi_pending = VecDeque::new();
        multi_engine.on_wfp_drop_dequeued(
            QueuedWfpDrop {
                exe_path: allow_exe.to_string(),
                exe_key: allow_exe_key.clone(),
                dst_ip: shared_dst,
                dst_port: 443,
                protocol: 6,
                timestamp_ms: now_ms + 1_000,
                os_filter_id: 3,
            },
            &mut multi_pending,
        );
        assert_eq!(
            multi_pending.len(),
            1,
            "multi-instance drop must still park when sibling only holds stale >60s DNS"
        );
        multi_engine.flush_ready_pending_wfp_drops(
            &stale_upd.instance_id,
            &allow_exe_key,
            "good.example",
            &stale_upd.accepted_ips,
            &mut multi_pending,
        );
        assert_eq!(
            multi_pending.len(),
            1,
            "stale-age sibling DNS must not prematurely wake parked multi-instance drop"
        );
        let fresh_upd = multi_engine
            .process_event_with_lane(
                &SensorEvent::DnsQuery {
                    pid: p_b.pid,
                    query_name: "good.example".to_string(),
                    query_type: 1,
                    resolved_ips: vec![shared_dst],
                    timestamp_ms: now_ms + 900,
                },
                EventLane::HighPriority,
            )
            .expect("fresh dns accepted");
        multi_engine.flush_ready_pending_wfp_drops(
            &fresh_upd.instance_id,
            &allow_exe_key,
            "good.example",
            &fresh_upd.accepted_ips,
            &mut multi_pending,
        );
        assert!(
            multi_pending.is_empty(),
            "fresh allowed sibling DNS must wake parked multi-instance drop"
        );

        // Post-exit shared-IP DomainPolicy Block preservation: if two blocked domains resolve
        // to `shared_ip`, the original process exits (clearing `entries`), and one domain
        // rotates away, `current_domains_by_ip_for_exe` must keep `shared_ip` blocked until
        // the second blocked domain also rotates away.
        let blk_exe = r"C:\Tools\shared_blk_post_exit.exe";
        let blk_store = LedrStore::open_in_memory().expect("open blk store");
        for (rid, dom) in [("R-BLK-A", "a.bad.example"), ("R-BLK-B", "b.bad.example")] {
            blk_store
                .upsert_rule(&ledr_proto::AllowlistRuleRecord {
                    rule_id: rid.to_string(),
                    scope: ledr_proto::RuleScope::NetworkBlock,
                    exe_path_pattern: blk_exe.to_string(),
                    sha256: Some(test_sha.clone()),
                    signer_subject: None,
                    root_thumbprint: None,
                    allowed_target: Some(dom.to_string()),
                    created_at_ms: now_ms - 10_000,
                    created_by: "test".to_string(),
                })
                .expect("seed block rule");
        }
        let blk_engine = DaemonEngine::start_with_dependencies(
            blk_store,
            SigmaEngine::default(),
            EarlyPruner::default(),
            DaemonConfig {
                outbound_firewall_enabled: true,
                ..DaemonConfig::default()
            },
            std::sync::Arc::new(StubDefense(std::sync::atomic::AtomicU64::new(100))),
            std::sync::Arc::new(StubNotifier),
            std::sync::Arc::new(FixedShaInspector(test_sha)),
        );
        if let Some(h) = blk_engine.worker_handle.lock().await.take() {
            h.abort();
            let _ = h.await;
        }
        let shared_blk_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 88));
        let moved_a_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 88));
        let moved_b_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 89));
        let bp1 = ProcessIdentity::new(9421, (now_ms as u64 + 11_644_473_600_000) * 10_000);
        let bp2 = ProcessIdentity::new(9422, (now_ms as u64 + 11_644_473_600_000) * 10_000);
        let _ = blk_engine.process_event_with_lane(
            &SensorEvent::ProcessStart {
                identity: bp1,
                parent_pid: 4,
                exe_path: blk_exe.to_string(),
                command_line: blk_exe.to_string(),
                user_sid: None,
            },
            EventLane::HighPriority,
        );
        let _ = blk_engine.process_event_with_lane(
            &SensorEvent::DnsQuery {
                pid: bp1.pid,
                query_name: "a.bad.example".to_string(),
                query_type: 1,
                resolved_ips: vec![shared_blk_ip],
                timestamp_ms: now_ms + 100,
            },
            EventLane::HighPriority,
        );
        let _ = blk_engine.process_event_with_lane(
            &SensorEvent::DnsQuery {
                pid: bp1.pid,
                query_name: "b.bad.example".to_string(),
                query_type: 1,
                resolved_ips: vec![shared_blk_ip],
                timestamp_ms: now_ms + 110,
            },
            EventLane::HighPriority,
        );
        assert!(blk_engine.has_active_wfp_filter(blk_exe, Some(shared_blk_ip), false));
        // `bp1` exits, clearing `ProcessDnsHistory::entries` completely.
        let _ = blk_engine.process_event_with_lane(
            &SensorEvent::ProcessStop {
                pid: bp1.pid,
                exit_time_100ns: (now_ms as u64 + 11_644_473_600_200) * 10_000,
                exit_code: 0,
            },
            EventLane::HighPriority,
        );
        let _ = blk_engine.process_event_with_lane(
            &SensorEvent::ProcessStart {
                identity: bp2,
                parent_pid: 4,
                exe_path: blk_exe.to_string(),
                command_line: blk_exe.to_string(),
                user_sid: None,
            },
            EventLane::HighPriority,
        );
        // `a.bad.example` moves off `shared_blk_ip`, but `b.bad.example` still maps to it.
        let _ = blk_engine.process_event_with_lane(
            &SensorEvent::DnsQuery {
                pid: bp2.pid,
                query_name: "a.bad.example".to_string(),
                query_type: 1,
                resolved_ips: vec![moved_a_ip],
                timestamp_ms: now_ms + 300,
            },
            EventLane::HighPriority,
        );
        assert!(
            blk_engine.has_active_wfp_filter(blk_exe, Some(shared_blk_ip), false),
            "shared_blk_ip must stay blocked while b.bad.example still points there in latest_domain_by_exe after bp1 exit"
        );
        // Once `b.bad.example` also moves off `shared_blk_ip`, the retired block is removed.
        let _ = blk_engine.process_event_with_lane(
            &SensorEvent::DnsQuery {
                pid: bp2.pid,
                query_name: "b.bad.example".to_string(),
                query_type: 1,
                resolved_ips: vec![moved_b_ip],
                timestamp_ms: now_ms + 400,
            },
            EventLane::HighPriority,
        );
        assert!(
            !blk_engine.has_active_wfp_filter(blk_exe, Some(shared_blk_ip), false),
            "shared_blk_ip block must be removed once both blocked domains rotated away"
        );
    });
}
