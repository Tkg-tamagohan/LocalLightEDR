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

    // 1 & 2. Family-independent acceptance: A(1000)->AAAA(3000)->A(2000) and reverse order
    //        AAAA(1000)->A(3000)->AAAA(2000).
    fn assert_family_independent_order(
        hist: &mut ProcessDnsHistory,
        inst: &str,
        exe: &str,
        query_name: &str,
        canon_domain: &str,
        ips: (IpAddr, IpAddr, IpAddr),
        msg: &str,
    ) {
        let (primary_1, other, primary_2) = ips;
        assert_eq!(
            hist.record_for_exe(inst, exe, query_name, &[primary_1], 1_000),
            vec![primary_1]
        );
        assert_eq!(
            hist.record_for_exe(inst, exe, query_name, &[other], 3_000),
            vec![other]
        );
        assert_eq!(
            hist.record_for_exe(inst, exe, query_name, &[primary_2], 2_000),
            vec![primary_2],
            "{msg}"
        );
        assert!(hist.lookup_for_process(inst, primary_1).is_none());
        assert_eq!(
            hist.lookup_for_process(inst, primary_2),
            Some((canon_domain.to_string(), 2_000))
        );
        assert_eq!(
            hist.lookup_for_process(inst, other),
            Some((canon_domain.to_string(), 3_000))
        );
        assert!(hist.is_domain_ip_superseded(exe, canon_domain, primary_1));
        assert!(!hist.is_domain_ip_superseded(exe, canon_domain, primary_2));
        assert!(!hist.is_domain_ip_superseded(exe, canon_domain, other));
    }

    // 1. A(1000) -> AAAA(3000) -> A(2000)
    assert_family_independent_order(
        &mut hist,
        "10:1",
        exe,
        "api.example.",
        "api.example",
        (v4_1, v6_1, v4_2),
        "newer IPv4 response at t=2000 must not be rejected by AAAA at t=3000",
    );
    // IPv4-mapped IPv6 address must map to the IPv4 family for superseding checks.
    let v4_1_mapped = IpAddr::V6(Ipv4Addr::new(198, 51, 100, 10).to_ipv6_mapped());
    let v4_2_mapped = IpAddr::V6(Ipv4Addr::new(198, 51, 100, 20).to_ipv6_mapped());
    assert!(hist.is_domain_ip_superseded(exe, "api.example", v4_1_mapped));
    assert!(!hist.is_domain_ip_superseded(exe, "api.example", v4_2_mapped));

    // 2. Reverse order: AAAA(1000) -> A(3000) -> AAAA(2000).
    assert_family_independent_order(
        &mut hist,
        "20:1",
        exe,
        "rev.example",
        "rev.example",
        (v6_1, v4_1, v6_2),
        "newer IPv6 response at t=2000 must not be rejected by A at t=3000",
    );

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
        exe_key: std::sync::Arc::from(exe),
        domains: vec![super::DomainTimestamp {
            domain: std::sync::Arc::from("api.example"),
            timestamp_ms: 1_000,
        }],
    };
    let v4_entry_cur = super::DnsHistoryEntry {
        exe_key: std::sync::Arc::from(exe),
        domains: vec![super::DomainTimestamp {
            domain: std::sync::Arc::from("api.example"),
            timestamp_ms: 2_000,
        }],
    };
    let v6_entry_cur = super::DnsHistoryEntry {
        exe_key: std::sync::Arc::from(exe),
        domains: vec![super::DomainTimestamp {
            domain: std::sync::Arc::from("api.example"),
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
    use super::helpers::{
        make_net_rule, make_queued_drop, send_dns, send_dns_typed, send_process_start,
        send_process_stop, start_stopped_engine, FixedShaInspector, TestDefense,
    };
    use super::super::wfp_drops::PendingWfpDropReason;
use super::{current_unix_ms, DaemonConfig, DaemonEngine, PendingWfpDrop, WfpRuleManager};
    use ledr_proto::{ProcessIdentity, RuleScope};
    use ledr_rules::{EarlyPruner, SigmaEngine};
    use ledr_store::LedrStore;
    use std::collections::VecDeque;
    use std::net::Ipv6Addr;
    use std::sync::Arc;
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

        send_process_start(&engine, proc_id, exe);

        let v4_new = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 20));
        let v4_stale = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
        let v6_new = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x42));

        let upd1 = send_dns(&engine, proc_id.pid, "svc.example", &[v4_new], now_ms + 200)
            .expect("fresh v4 dns accepted");
        assert_eq!(upd1.instance_id, inst_id);
        assert_eq!(upd1.exe_key, exe_key);
        assert_eq!(upd1.accepted_ips, vec![v4_new]);

        // Stale v4-only DNS response must yield `None` (no accepted IPs).
        assert!(
            send_dns(&engine, proc_id.pid, "svc.example", &[v4_stale], now_ms + 100).is_none(),
            "stale DNS response must return None and never wake pending WFP drops"
        );

        // Mixed query: stale v4 is dropped, fresh v6 is returned in `accepted_ips`.
        let upd_mixed = send_dns_typed(
            &engine,
            proc_id.pid,
            "svc.example",
            28,
            &[v4_stale, v6_new],
            now_ms + 150,
        )
        .expect("mixed query must accept v6");
        assert_eq!(upd_mixed.accepted_ips, vec![v6_new]);

        // Even with `candidates.len() == 1`, `flush_ready_pending_wfp_drops` must keep a
        // pending entry parked when `lookup_for_process(dns_inst_id, dst_ip)` is `None`.
        let mut pending = VecDeque::new();
        let future_deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        pending.push_back(PendingWfpDrop {
            item: make_queued_drop(exe, v4_stale, now_ms + 250, 1),
            deadline: future_deadline,
            dns_deadline: Some(future_deadline),
            reason: PendingWfpDropReason::DnsGrace,
            parked_single_instance_id: Some(inst_id.clone()),
            confirmed_ambiguous: false,
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
            item: make_queued_drop(exe, v6_new, now_ms + 250, 2),
            deadline: future_deadline,
            dns_deadline: Some(future_deadline),
            reason: PendingWfpDropReason::DnsGrace,
            parked_single_instance_id: Some(inst_id.clone()),
            confirmed_ambiguous: false,
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
        let test_sha = "a".repeat(64);
        let allow_exe = r"C:\Temp\multi_r03.exe";
        let allow_exe_key = WfpRuleManager::exe_key(allow_exe);
        let allow_store = LedrStore::open_in_memory().expect("open allow store");
        allow_store
            .upsert_rule(&make_net_rule(
                "R-MULTI-ALLOW",
                RuleScope::NetworkAllow,
                allow_exe,
                &test_sha,
                "good.example",
                now_ms - 10_000,
            ))
            .expect("seed allow rule");
        let multi_engine = start_stopped_engine(
            allow_store,
            DaemonConfig {
                outbound_firewall_enabled: true,
                wfp_drop_dns_grace_ms: 500,
                ..DaemonConfig::default()
            },
            Arc::new(TestDefense::new(1)),
            Arc::new(FixedShaInspector(test_sha.clone())),
        )
        .await;
        let proc_start_ms = now_ms - super::AMBIGUOUS_DNS_HISTORY_MAX_AGE_MS - 20_000;
        let p_a =
            ProcessIdentity::new(9411, (proc_start_ms as u64 + 11_644_473_600_000) * 10_000);
        let p_b =
            ProcessIdentity::new(9412, (proc_start_ms as u64 + 11_644_473_600_000) * 10_000);
        for pid_id in [p_a, p_b] {
            send_process_start(&multi_engine, pid_id, allow_exe);
        }
        let shared_dst = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77));
        // Seed stale DNS (> AMBIGUOUS_DNS_HISTORY_MAX_AGE_MS old) on sibling `p_a`.
        let stale_upd = send_dns(
            &multi_engine,
            p_a.pid,
            "good.example",
            &[shared_dst],
            now_ms - super::AMBIGUOUS_DNS_HISTORY_MAX_AGE_MS - 5_000,
        )
        .expect("stale-age dns accepted as initial");
        let mut multi_pending = VecDeque::new();
        multi_engine.on_wfp_drop_dequeued(
            make_queued_drop(allow_exe, shared_dst, now_ms + 1_000, 3),
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
        let fresh_upd = send_dns(
            &multi_engine,
            p_b.pid,
            "good.example",
            &[shared_dst],
            now_ms + 900,
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
                .upsert_rule(&make_net_rule(
                    rid,
                    RuleScope::NetworkBlock,
                    blk_exe,
                    &test_sha,
                    dom,
                    now_ms - 10_000,
                ))
                .expect("seed block rule");
        }
        let blk_engine = start_stopped_engine(
            blk_store,
            DaemonConfig {
                outbound_firewall_enabled: true,
                ..DaemonConfig::default()
            },
            Arc::new(TestDefense::new(100)),
            Arc::new(FixedShaInspector(test_sha)),
        )
        .await;
        let shared_blk_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 88));
        let moved_a_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 88));
        let moved_b_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 89));
        let bp1 = ProcessIdentity::new(9421, (now_ms as u64 + 11_644_473_600_000) * 10_000);
        let bp2 = ProcessIdentity::new(9422, (now_ms as u64 + 11_644_473_600_000) * 10_000);
        send_process_start(&blk_engine, bp1, blk_exe);
        let _ = send_dns(&blk_engine, bp1.pid, "a.bad.example", &[shared_blk_ip], now_ms + 100);
        let _ = send_dns(&blk_engine, bp1.pid, "b.bad.example", &[shared_blk_ip], now_ms + 110);
        assert!(blk_engine.has_active_wfp_filter(blk_exe, Some(shared_blk_ip), false));
        // `bp1` exits, clearing `ProcessDnsHistory::entries` completely.
        send_process_stop(
            &blk_engine,
            bp1.pid,
            (now_ms as u64 + 11_644_473_600_200) * 10_000,
        );
        send_process_start(&blk_engine, bp2, blk_exe);
        // `a.bad.example` moves off `shared_blk_ip`, but `b.bad.example` still maps to it.
        let _ = send_dns(&blk_engine, bp2.pid, "a.bad.example", &[moved_a_ip], now_ms + 300);
        assert!(
            blk_engine.has_active_wfp_filter(blk_exe, Some(shared_blk_ip), false),
            "shared_blk_ip must stay blocked while b.bad.example still points there in latest_domain_by_exe after bp1 exit"
        );
        // Once `b.bad.example` also moves off `shared_blk_ip`, the retired block is removed.
        let _ = send_dns(&blk_engine, bp2.pid, "b.bad.example", &[moved_b_ip], now_ms + 400);
        assert!(
            !blk_engine.has_active_wfp_filter(blk_exe, Some(shared_blk_ip), false),
            "shared_blk_ip block must be removed once both blocked domains rotated away"
        );
    });
}
