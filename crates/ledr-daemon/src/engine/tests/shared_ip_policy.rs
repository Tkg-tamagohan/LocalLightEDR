use super::ProcessDnsHistory;
use std::net::{IpAddr, Ipv4Addr};

/// `DAEMON-P3-46A` (`#2` / `BUG_..._0001`): `ProcessDnsHistory` retains multiple bounded
/// timestamped domain candidates per `(process_instance_id, IpAddr)` without dropping delayed
/// cross-domain responses, evicts only the migrated domain on IP rotation, enforces the
/// `MAX_DOMAINS_PER_PROCESS_IP` bound (pruning superseded entries first), and unifies decision
/// precedence (`BlockedByRule > AllowedByRule > newest unallowed`) across grace parking,
/// early wakeup, WFP drop triage, and `NetworkConnect` hint resolution.
#[test]
fn daemon_p3_46a_shared_ip_multi_domain_history_and_common_decision_precedence() {
    use super::helpers::{
        assert_domain_policy_hints, make_net_rule, make_pending_net_alert, make_queued_drop,
        send_connect, send_dns, send_process_start, send_process_stop, start_stopped_engine,
        FixedShaInspector, TestDefense,
    };
    use super::{
        current_unix_ms, select_outbound_decision_for_domains, DaemonConfig, WfpRuleManager,
        MAX_DOMAINS_PER_PROCESS_IP,
    };
    use ledr_proto::{ProcessIdentity, RuleScope};
    use ledr_rules::{BinaryIdentity, OutboundDecision};
    use ledr_store::LedrStore;
    use std::collections::VecDeque;
    use std::sync::Arc;

    // Part A: `ProcessDnsHistory` multi-domain retention, selective eviction, and cap bound.
    let mut hist = ProcessDnsHistory::new(64);
    let exe = r"c:\temp\shared_cdn_app.exe";
    let shared_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77));
    let moved_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77));

    assert_eq!(
        hist.record_for_exe("10:1", exe, "other.example.", &[shared_ip], 2_000),
        vec![shared_ip]
    );
    assert_eq!(
        hist.record_for_exe("10:1", exe, "allowed.example.", &[shared_ip], 1_500),
        vec![shared_ip]
    );
    assert_eq!(
        hist.lookup_domains_for_process("10:1", shared_ip),
        vec![
            ("other.example".to_string(), 2_000),
            ("allowed.example".to_string(), 1_500),
        ],
        "delayed cross-domain DNS on shared IP must be retained alongside newer domain"
    );
    assert_eq!(
        hist.lookup_for_process("10:1", shared_ip),
        Some(("other.example".to_string(), 2_000))
    );
    assert_eq!(
        hist.lookup_fresh_domains_for_process("10:1", shared_ip, 61_700, 60_000),
        vec![("other.example".to_string(), 2_000)],
        "freshness window must filter each domain candidate independently"
    );
    assert_eq!(
        hist.lookup_fresh_domains_for_process("10:1", shared_ip, 61_500, 60_000),
        vec![
            ("other.example".to_string(), 2_000),
            ("allowed.example".to_string(), 1_500),
        ]
    );
    assert_eq!(
        hist.domains_for_exe_ip(exe, shared_ip),
        vec!["allowed.example".to_string(), "other.example".to_string()]
    );
    assert!(hist.another_process_resolved(Some("20:2"), "allowed.example", shared_ip, 2_100));
    assert!(!hist.another_process_resolved(Some("10:1"), "allowed.example", shared_ip, 2_100));

    // Rotating `other.example` away from `shared_ip` removes ONLY `other.example` and keeps
    // `allowed.example` intact on `shared_ip`.
    assert_eq!(
        hist.record_for_exe("10:1", exe, "other.example", &[moved_ip], 3_000),
        vec![moved_ip]
    );
    assert_eq!(
        hist.lookup_domains_for_process("10:1", shared_ip),
        vec![("allowed.example".to_string(), 1_500)],
        "rotating other.example must not evict allowed.example from shared_ip"
    );
    // Same-domain re-record must not regress timestamp_ms.
    hist.record_for_exe("10:1", exe, "allowed.example", &[shared_ip], 1_200);
    assert_eq!(
        hist.lookup_domains_for_process("10:1", shared_ip),
        vec![("allowed.example".to_string(), 1_500)]
    );
    hist.record_for_exe("10:1", exe, "allowed.example", &[shared_ip], 2_500);
    assert_eq!(
        hist.lookup_domains_for_process("10:1", shared_ip),
        vec![("allowed.example".to_string(), 2_500)]
    );

    // Boundedness at `MAX_DOMAINS_PER_PROCESS_IP` (16): superseded candidates drop before live
    // entries, and live overflow evicts the oldest `timestamp_ms`.
    let mut bounded = ProcessDnsHistory::new(64);
    let cap_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 90));
    let away_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 90));
    // Insert a newer superseded entry (`sup.example @ 5000`) plus 15 older live entries
    // (`live-0..14 @ 1000..1014`). Because `sup.example` is migrated via a different process of
    // the same exe only after recording, simulate superseding via a sibling with `exe_key`.
    bounded.record_for_exe("50:1", exe, "sup.example", &[cap_ip], 5_000);
    for i in 0..(MAX_DOMAINS_PER_PROCESS_IP - 1) {
        bounded.record_for_exe(
            "50:1",
            exe,
            &format!("live-{i:02}.example"),
            &[cap_ip],
            1_000 + i as i64,
        );
    }
    // Mark `sup.example` superseded in `latest_domain_by_exe` without erasing from `50:1` by
    // simulating an earlier timestamp entry in `50:1` directly, then inserting a 17th live domain.
    bounded
        .latest_domain_by_exe
        .get_mut(&(std::sync::Arc::from(exe), std::sync::Arc::from("sup.example")))
        .expect("sup latest")
        .ipv4 = Some((vec![away_ip], 6_000));
    bounded.record_for_exe("50:1", exe, "live-15.example", &[cap_ip], 1_050);
    let doms_after_sup = bounded.lookup_domains_for_process("50:1", cap_ip);
    assert_eq!(doms_after_sup.len(), MAX_DOMAINS_PER_PROCESS_IP);
    assert!(
        doms_after_sup.iter().any(|(d, _)| d == "live-00.example"),
        "superseded candidate must be pruned before evicting oldest live domain live-00.example"
    );
    // Inserting 4 more live domains keeps total capped at 16 and evicts oldest live timestamps.
    for extra in 16..20 {
        bounded.record_for_exe(
            "50:1",
            exe,
            &format!("live-{extra:02}.example"),
            &[cap_ip],
            2_000 + extra as i64,
        );
    }
    let doms_capped = bounded.lookup_domains_for_process("50:1", cap_ip);
    assert_eq!(doms_capped.len(), MAX_DOMAINS_PER_PROCESS_IP);
    assert!(
        !doms_capped.iter().any(|(d, _)| d == "live-00.example"),
        "oldest live timestamp must be evicted when exceeding MAX_DOMAINS_PER_PROCESS_IP"
    );
    assert!(doms_capped.iter().any(|(d, _)| d == "live-19.example"));

    // Part B: Common priority helper `select_outbound_decision_for_domains`.
    let sha = "a".repeat(64);
    let app_identity = BinaryIdentity {
        exe_path: r"C:\Temp\shared_cdn_app.exe".to_string(),
        sha256: Some(sha.clone()),
        authenticode: None,
    };
    let os_identity = BinaryIdentity {
        exe_path: r"C:\Windows\System32\svchost.exe".to_string(),
        sha256: Some(sha.clone()),
        authenticode: None,
    };
    let allow_rule = make_net_rule(
        "R-ALLOW",
        RuleScope::NetworkAllow,
        &app_identity.exe_path,
        &sha,
        "allowed.example",
        1,
    );
    let block_rule = make_net_rule(
        "R-BLOCK",
        RuleScope::NetworkBlock,
        &app_identity.exe_path,
        &sha,
        "blocked.example",
        2,
    );
    let rules = vec![allow_rule.clone(), block_rule];

    // 1. ProtectedOs short-circuits immediately.
    assert_eq!(
        select_outbound_decision_for_domains(
            &os_identity,
            shared_ip,
            &[("blocked.example".to_string(), 3_000)],
            &rules,
        ),
        (OutboundDecision::ProtectedOs, None)
    );
    // 2. AllowedByRule beats newer unallowed candidate.
    assert_eq!(
        select_outbound_decision_for_domains(
            &app_identity,
            shared_ip,
            &[
                ("other.example".to_string(), 2_000),
                ("allowed.example".to_string(), 1_500),
            ],
            &rules,
        ),
        (
            OutboundDecision::AllowedByRule {
                rule_id: "R-ALLOW".to_string(),
            },
            Some("allowed.example".to_string())
        )
    );
    // 3. BlockedByRule beats newer AllowedByRule (deny-overrides-allow).
    assert_eq!(
        select_outbound_decision_for_domains(
            &app_identity,
            shared_ip,
            &[
                ("allowed.example".to_string(), 3_000),
                ("other.example".to_string(), 2_000),
                ("blocked.example".to_string(), 1_500),
            ],
            &rules,
        ),
        (
            OutboundDecision::BlockedByRule {
                rule_id: "R-BLOCK".to_string(),
            },
            Some("blocked.example".to_string())
        )
    );
    // 4. Only unallowed candidates -> newest timestamp, deterministic case-insensitive tie-break.
    let (unallowed_dec, unallowed_hint) = select_outbound_decision_for_domains(
        &app_identity,
        shared_ip,
        &[
            ("Zeta.Example.".to_string(), 2_000),
            ("alpha.example".to_string(), 2_000),
            ("older.example".to_string(), 1_000),
        ],
        &rules,
    );
    assert!(matches!(
        unallowed_dec,
        OutboundDecision::PreemptiveRestrict(_)
    ));
    assert_eq!(unallowed_hint.as_deref(), Some("alpha.example"));
    // 5. Empty candidates -> base decision with None; `ProcessDnsHistory::new(0)` clamps to 1.
    let (empty_dec, empty_hint) =
        select_outbound_decision_for_domains(&app_identity, shared_ip, &[], &rules);
    assert!(matches!(empty_dec, OutboundDecision::PreemptiveRestrict(_)));
    assert!(empty_hint.is_none());
    let mut zero_cap = ProcessDnsHistory::new(0);
    zero_cap.record_for_exe("1:1", exe, "z1.example", &[shared_ip], 100);
    zero_cap.record_for_exe("1:1", exe, "z2.example", &[moved_ip], 200);
    assert_eq!(zero_cap.entries.len(), 1);
    assert_eq!(zero_cap.latest_domain_by_exe.len(), 1);

    // Part C: Engine-level grace parking, non-premature wakeup on unallowed domain, delayed
    // allowed wakeup without mis-suspension or permit revocation, and `dns_history_capacity`.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build rt");
    rt.block_on(async {
        let store = LedrStore::open_in_memory().expect("open store");
        store.upsert_rule(&allow_rule).expect("seed allow rule");
        let defense = Arc::new(TestDefense::new(1));
        let engine = start_stopped_engine(
            store.clone(),
            DaemonConfig {
                outbound_firewall_enabled: true,
                wfp_drop_dns_grace_ms: 500,
                dns_history_capacity: 4,
                ..DaemonConfig::default()
            },
            defense.clone(),
            Arc::new(FixedShaInspector(sha.clone())),
        )
        .await;

        let now_ms = current_unix_ms();
        let exe_path = r"C:\Temp\shared_cdn_app.exe";
        let exe_key = WfpRuleManager::exe_key(exe_path);
        let p1 = ProcessIdentity::new(9601, (now_ms as u64 + 11_644_473_600_000) * 10_000);
        let p2 = ProcessIdentity::new(9602, (now_ms as u64 + 11_644_473_600_000) * 10_000);
        send_process_start(&engine, p1, exe_path);
        send_process_start(&engine, p2, r"C:\Tools\other_app.exe");
        assert!(engine.has_active_wfp_filter(exe_path, None, false));

        // Newer unallowed `other.example` arrives first on `shared_ip`.
        let _ = send_dns(&engine, p1.pid, "other.example", &[shared_ip], now_ms + 2_000);

        // Drop arrives while only unallowed `other.example` is in history -> MUST park because
        // a domain-scoped NetworkAllow rule exists for `exe_path`.
        let mut pending = VecDeque::new();
        engine.on_wfp_drop_dequeued(
            make_queued_drop(exe_path, shared_ip, now_ms + 2_050, 1),
            &mut pending,
        );
        assert_eq!(
            pending.len(),
            1,
            "single-candidate drop with only unallowed domain must park during grace window"
        );

        // Another unallowed domain arriving must NOT prematurely wake the parked drop.
        let upd_third = send_dns(&engine, p1.pid, "third.example", &[shared_ip], now_ms + 2_100)
            .expect("third.example accepted");
        engine.flush_ready_pending_wfp_drops(
            &upd_third.instance_id,
            &exe_key,
            "third.example",
            &upd_third.accepted_ips,
            &mut pending,
        );
        assert_eq!(
            pending.len(),
            1,
            "additional unallowed domain must not shorten grace window"
        );

        // Delayed `allowed.example` (t=1500 < 2000) arrives -> pre-materializes IP Permit and
        // wakes parked drop immediately without suspending or revoking the Permit!
        let upd_allowed =
            send_dns(&engine, p1.pid, "allowed.example", &[shared_ip], now_ms + 1_500)
                .expect("delayed allowed.example accepted");
        assert!(engine.has_active_wfp_filter(exe_path, Some(shared_ip), true));
        engine.flush_ready_pending_wfp_drops(
            &upd_allowed.instance_id,
            &exe_key,
            "allowed.example",
            &upd_allowed.accepted_ips,
            &mut pending,
        );
        assert!(
            pending.is_empty(),
            "delayed allowed.example must wake parked drop immediately"
        );
        assert!(
            engine.has_active_wfp_filter(exe_path, Some(shared_ip), true),
            "IP Permit for allowed.example must survive WFP drop triage"
        );
        assert_eq!(defense.suspends(), 0);
        assert!(store.list_alerts(None, 20).unwrap().is_empty());

        // Another process also resolving `allowed.example` must NOT cause `p1`'s own
        // `allowed.example` raw hint to be mistaken for cross-process contamination.
        let _ = send_dns(&engine, p2.pid, "allowed.example", &[shared_ip], now_ms + 2_200);
        let resolved_cands = engine.resolve_effective_domain_candidates(
            Some(&p1.instance_id()),
            Some(exe_path),
            shared_ip,
            Some("allowed.example"),
            now_ms + 2_250,
        );
        assert!(
            resolved_cands.iter().any(|(d, _)| d == "allowed.example"),
            "own candidate set must retain allowed.example even when another process resolved it"
        );

        // Part D: Named shared-IP Permit reconciliation + deny-overrides-allow suppression in
        // `prematerialize_domain_wfp_filters` + no duplicate failure counting in
        // `deploy_persisted_network_rules_with_baseline`.
        // Currently `shared_ip` has a named `DomainPolicy` Permit tagged `["allowed.example"]`
        // AND `other.example` is in `p1`'s DNS history for `shared_ip`.
        // Adding `NetworkBlock("other.example")` MUST revoke the named shared-IP Permit!
        let block_other_rule = make_net_rule(
            "R-BLK-OTHER",
            RuleScope::NetworkBlock,
            exe_path,
            &sha,
            "other.example",
            now_ms + 2_300,
        );
        engine
            .upsert_policy_rule(&block_other_rule)
            .expect("upsert block rule for other.example");
        assert!(
            !engine.has_active_wfp_filter(exe_path, Some(shared_ip), true),
            "blocking another domain sharing the same IP must revoke named DomainPolicy Permit"
        );

        // Re-querying `allowed.example -> shared_ip` while `other.example` is still active on
        // `shared_ip` MUST NOT re-create the Permit (deny-overrides-allow in prematerialize).
        let _ = send_dns(&engine, p1.pid, "allowed.example", &[shared_ip], now_ms + 2_400);
        assert!(
            !engine.has_active_wfp_filter(exe_path, Some(shared_ip), true),
            "prematerialize must suppress Permit when another active domain on shared_ip is blocked"
        );

        // Failure deduplication: install a Permit tagged `["other.example", "allowed.example"]`
        // while `remove_wfp_rule` fails, then reconcile -> `reconcile` fails removal once, and
        // `deploy_persisted_network_rules_with_baseline` must NOT double-count `rep.failed`.
        {
            let mut fw = engine.firewall.lock().unwrap();
            fw.ensure_ip_permit_for_domain_hints(
                exe_path,
                shared_ip,
                &["allowed.example", "other.example"],
                &*defense,
            )
            .expect("install multi-hint permit");
        }
        defense.set_fail_removes(true);
        let rep_dup_check = engine.deploy_persisted_network_rules();
        defense.set_fail_removes(false);
        assert_eq!(
            rep_dup_check.failed, 1,
            "failed removal of shared-IP Permit must not be double-counted across reconcile + DNS cross-check"
        );
        assert_eq!(rep_dup_check.failed_ops.len(), 1);
        assert!(rep_dup_check.failed_ops[0]
            .source_rule_ids
            .contains(&"R-BLK-OTHER".to_string()));

        // Part E: End-to-end `delete_policy_rule("R-ALLOW")` rollback attribution when Step 1
        // fails removing a Permit tagged ONLY `["allowed.example"]` while Step 2 also finds
        // `R-BLK-OTHER` via DNS history — deleting `R-ALLOW` MUST fail and roll back SQLite,
        // while an unrelated domain rule on the same exe STILL succeeds!
        {
            let mut fw = engine.firewall.lock().unwrap();
            let _ = fw.remove_domain_policy_permit(exe_path, shared_ip, &*defense);
            fw.ensure_ip_permit_for_domain_rule(
                exe_path,
                shared_ip,
                "allowed.example",
                &*defense,
            )
            .expect("install allowed-only permit");
        }
        defense.set_fail_removes(true);
        let del_res = engine.delete_policy_rule("R-ALLOW");
        assert!(
            matches!(del_res, Err(super::PolicyRuleError::FirewallSync(_))),
            "delete_policy_rule(R-ALLOW) must fail and roll back when Permit removal fails even if DNS cross-check also finds R-BLK-OTHER (got {del_res:?})"
        );
        assert!(
            store.get_rule("R-ALLOW").unwrap().is_some(),
            "R-ALLOW must be rolled back into SQLite after failed Permit removal"
        );
        let unrelated_allow = make_net_rule(
            "R-UNRELATED-ALLOW",
            RuleScope::NetworkAllow,
            exe_path,
            &sha,
            "unrelated.example",
            now_ms + 2_450,
        );
        engine
            .upsert_policy_rule(&unrelated_allow)
            .expect("unrelated domain rule save on same exe must succeed");
        defense.set_fail_removes(false);
        let _ = engine.deploy_persisted_network_rules();

        // Part F: `AllowPermanent` multi-domain hint propagation + exe-level deny-overrides-allow
        // suppression across sibling/exited process (`latest_domain_by_exe`), AND
        // `evaluate_and_handle_outbound_connect` preserving that Permit suppression!
        let clean_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 78));
        let _ = send_dns(&engine, p1.pid, "clean-a.example", &[clean_ip], now_ms + 2_500);
        let _ = send_dns(&engine, p1.pid, "clean-b.example", &[clean_ip], now_ms + 2_510);
        let clean_alert = make_pending_net_alert(
            "AL-P3-46A-CLEAN",
            now_ms + 2_520,
            "LEDR-NET-HIGH-RISK-PATH",
            "Clean multi-domain alert",
            Some(p1.instance_id()),
            serde_json::json!({
                "exe_path": exe_path,
                "dst_ip": clean_ip.to_string(),
                "domain_hint": "clean-a.example",
                "sha256": sha,
            }),
        );
        store.record_alert(&clean_alert).expect("record clean alert");
        engine
            .resolve_alert(
                &clean_alert.alert_id,
                ledr_proto::AlertDecision::AllowPermanent {
                    use_signer_if_available: false,
                    allow_dest: Some("clean-a.example".to_string()),
                },
            )
            .expect("AllowPermanent clean multi-domain");
        assert_domain_policy_hints(
            &engine,
            exe_path,
            clean_ip,
            &["clean-a.example", "clean-b.example"],
            "AllowPermanent must propagate all candidate domain hints on clean shared IP",
        );

        // Exe-level deny-overrides-allow on shared IP where sibling `p3` resolved blocked
        // `other.example` and exited (leaving `latest_domain_by_exe` active with no IP Block
        // filter yet), while `p1` resolved `share-allow.example` on the same IP.
        let shared_deny_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 79));
        let p3 = ProcessIdentity::new(9603, (now_ms as u64 + 11_644_473_600_000) * 10_000);
        send_process_start(&engine, p3, exe_path);
        // Temporarily remove R-BLK-OTHER before p3 resolves so no DomainPolicy Block is
        // materialized on `shared_deny_ip`, then re-insert R-BLK-OTHER and exit p3.
        engine
            .delete_policy_rule("R-BLK-OTHER")
            .expect("remove block before p3 dns");
        let _ = send_dns(&engine, p3.pid, "other.example", &[shared_deny_ip], now_ms + 2_600);
        send_process_stop(
            &engine,
            p3.pid,
            ((now_ms + 2_610) as u64 + 11_644_473_600_000) * 10_000,
        );
        engine
            .upsert_policy_rule(&block_other_rule)
            .expect("re-insert block after p3 exit");
        let _ = send_dns(&engine, p1.pid, "share-allow.example", &[shared_deny_ip], now_ms + 2_620);
        assert!(
            !engine.has_active_wfp_filter(exe_path, Some(shared_deny_ip), false),
            "no IP Block filter exists yet on shared_deny_ip"
        );
        let deny_share_alert = make_pending_net_alert(
            "AL-P3-46A-DENY-SHARE",
            now_ms + 2_630,
            "LEDR-NET-HIGH-RISK-PATH",
            "Shared deny IP alert",
            Some(p1.instance_id()),
            serde_json::json!({
                "exe_path": exe_path,
                "dst_ip": shared_deny_ip.to_string(),
                "domain_hint": "share-allow.example",
                "sha256": sha,
            }),
        );
        store
            .record_alert(&deny_share_alert)
            .expect("record deny-share alert");
        engine
            .resolve_alert(
                &deny_share_alert.alert_id,
                ledr_proto::AlertDecision::AllowPermanent {
                    use_signer_if_available: false,
                    allow_dest: Some("share-allow.example".to_string()),
                },
            )
            .expect("AllowPermanent succeeds saving rule");
        assert!(
            !engine.has_active_wfp_filter(exe_path, Some(shared_deny_ip), true),
            "AllowPermanent must suppress IP Permit when exe-wide DNS history has blocked other.example on shared_deny_ip"
        );
        // Subsequent outbound connect from `p1` (which only sees `share-allow.example` in its
        // own per-instance history) must ALSO keep the exe-wide WFP Permit suppressed!
        send_connect(&engine, p1.pid, shared_deny_ip, Some("share-allow.example"), now_ms + 2_640);
        assert!(
            !engine.has_active_wfp_filter(exe_path, Some(shared_deny_ip), true),
            "evaluate_and_handle_outbound_connect must NOT install exe-wide IP Permit while exe-level blocked domain shares shared_deny_ip"
        );

        // Verify `DaemonConfig::dns_history_capacity` (`4`) bounds `latest_domain_by_exe`.
        for idx in 0..6 {
            let _ = send_dns(
                &engine,
                p2.pid,
                &format!("cap-{idx}.example"),
                &[IpAddr::V4(Ipv4Addr::new(198, 51, 100, 100 + idx))],
                now_ms + 3_000 + idx as i64,
            );
        }
        let latest_len = engine
            .process_dns_history
            .lock()
            .unwrap()
            .latest_domain_by_exe
            .len();
        assert!(
            latest_len <= 4,
            "DaemonConfig::dns_history_capacity must bound latest_domain_by_exe (got {latest_len})"
        );

        // Part G, H, I: Dedicated clean engine covering:
        // - G: `BlockedByRule` DomainPolicy Block hint hygiene (pure CIDR, wildcard IP,
        //      hybrid CIDR + domain, and multi-domain blocks across `reconcile_persisted_rules_with_baseline`)
        // - H: `AllowPermanent` on ambiguous (`process_instance_id: None`, `candidate_instance_ids`)
        //      alerts (multi-hint propagation + exe-level deny-overrides-allow suppression)
        // - I: `handle_ambiguous_wfp_drop` with multiple fresh domains on a shared IP (CIDR allow
        //      multi-hint Permit, CIDR allow deny-overrides-allow without sticky IP block and
        //      overriding an existing live Permit, non-CIDR live Permit suppression / no-Permit
        //      alert / blocked-candidate non-suppression, and CIDR Block pure vs hybrid hints).
        let store_g = LedrStore::open_in_memory().expect("open store_g");
        let defense_g = Arc::new(TestDefense::new(100));
        let engine_g = start_stopped_engine(
            store_g.clone(),
            DaemonConfig {
                outbound_firewall_enabled: true,
                wfp_drop_dns_grace_ms: 500,
                dns_history_capacity: 64,
                ..DaemonConfig::default()
            },
            defense_g.clone(),
            Arc::new(FixedShaInspector(sha.clone())),
        )
        .await;

        let exe_g = r"C:\Temp\block_hygiene_app.exe";
        let gp1 = ProcessIdentity::new(9701, (now_ms as u64 + 11_644_473_600_000) * 10_000);
        send_process_start(&engine_g, gp1, exe_g);
        assert!(engine_g.has_active_wfp_filter(exe_g, None, false));

        let mk_net_rule = |rule_id: &str, scope: RuleScope, target: &str, created_at_ms: i64| {
            make_net_rule(rule_id, scope, exe_g, &sha, target, created_at_ms)
        };

        // Part G1: Pure CIDR NetworkBlock connect (with no DNS and with unblocked domain) and
        // prematerialize must keep `domain_hints: []` (never tagging CIDR literal or innocent domain).
        let cidr_no_dns_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
        let cidr_innocent_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11));
        let cidr_premat_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 12));
        let _ = send_dns(&engine_g, gp1.pid, "innocent.example", &[cidr_innocent_ip], now_ms + 100);
        engine_g
            .upsert_policy_rule(&mk_net_rule(
                "R-CIDR-PURE",
                RuleScope::NetworkBlock,
                "203.0.113.0/24",
                now_ms + 105,
            ))
            .expect("upsert pure CIDR block");
        assert!(!engine_g.has_active_wfp_filter(exe_g, Some(cidr_no_dns_ip), false));
        assert!(!engine_g.has_active_wfp_filter(exe_g, Some(cidr_innocent_ip), false));

        send_connect(&engine_g, gp1.pid, cidr_no_dns_ip, None, now_ms + 110);
        assert_domain_policy_hints(
            &engine_g,
            exe_g,
            cidr_no_dns_ip,
            &[],
            "pure CIDR connect without DNS must leave domain_hints empty, not tag CIDR literal",
        );
        send_connect(
            &engine_g,
            gp1.pid,
            cidr_innocent_ip,
            Some("innocent.example"),
            now_ms + 115,
        );
        assert_domain_policy_hints(
            &engine_g,
            exe_g,
            cidr_innocent_ip,
            &[],
            "pure CIDR connect with unblocked domain must leave domain_hints empty",
        );
        // When any domain-scoped rule exists (enabling DNS prematerialization), a DnsQuery
        // for an unblocked domain resolving inside `R-CIDR-PURE` must also materialize an
        // untagged (`domain_hints: []`) CIDR block rather than tagging `innocent2.example`.
        engine_g
            .upsert_policy_rule(&mk_net_rule(
                "R-UNRELATED-DOM-G1",
                RuleScope::NetworkBlock,
                "unrelated-g1.example",
                now_ms + 118,
            ))
            .expect("upsert unrelated domain rule to enable prematerialize");
        let _ = send_dns(&engine_g, gp1.pid, "innocent2.example", &[cidr_premat_ip], now_ms + 120);
        assert_domain_policy_hints(
            &engine_g,
            exe_g,
            cidr_premat_ip,
            &[],
            "pure CIDR prematerialize must keep domain_hints empty",
        );
        engine_g
            .delete_policy_rule("R-UNRELATED-DOM-G1")
            .expect("delete unrelated domain rule");
        engine_g
            .delete_policy_rule("R-CIDR-PURE")
            .expect("delete pure CIDR block");
        assert!(!engine_g.has_active_wfp_filter(exe_g, Some(cidr_no_dns_ip), false));
        assert!(!engine_g.has_active_wfp_filter(exe_g, Some(cidr_innocent_ip), false));
        assert!(!engine_g.has_active_wfp_filter(exe_g, Some(cidr_premat_ip), false));

        // Part G2: Hybrid CIDR + domain block where `innocent.example` is newer than
        // `blk.example`. Connect must tag ONLY `["blk.example"]`, and deleting `R-CIDR-HYBRID`
        // must keep the block filter active until `R-BLK-HYBRID` is also deleted.
        let hybrid_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 20));
        let _ = send_dns(&engine_g, gp1.pid, "blk.example", &[hybrid_ip], now_ms + 200);
        let _ = send_dns(&engine_g, gp1.pid, "innocent.example", &[hybrid_ip], now_ms + 300);
        engine_g
            .upsert_policy_rule(&mk_net_rule(
                "R-CIDR-HYBRID",
                RuleScope::NetworkBlock,
                "203.0.113.0/24",
                now_ms + 305,
            ))
            .expect("upsert hybrid CIDR block");
        engine_g
            .upsert_policy_rule(&mk_net_rule(
                "R-BLK-HYBRID",
                RuleScope::NetworkBlock,
                "blk.example",
                now_ms + 306,
            ))
            .expect("upsert hybrid domain block");
        assert!(!engine_g.has_active_wfp_filter(exe_g, Some(hybrid_ip), false));

        send_connect(&engine_g, gp1.pid, hybrid_ip, None, now_ms + 310);
        assert_domain_policy_hints(
            &engine_g,
            exe_g,
            hybrid_ip,
            &["blk.example"],
            "hybrid CIDR + domain connect must record only domain-specific blocked hint blk.example",
        );
        engine_g
            .delete_policy_rule("R-CIDR-HYBRID")
            .expect("delete hybrid CIDR block");
        assert!(
            engine_g.has_active_wfp_filter(exe_g, Some(hybrid_ip), false),
            "deleting R-CIDR-HYBRID must keep DomainPolicy Block alive while R-BLK-HYBRID remains"
        );
        assert_domain_policy_hints(&engine_g, exe_g, hybrid_ip, &["blk.example"], "");
        engine_g
            .delete_policy_rule("R-BLK-HYBRID")
            .expect("delete hybrid domain block");
        assert!(!engine_g.has_active_wfp_filter(exe_g, Some(hybrid_ip), false));

        // Part G3: Two domain blocks (`R-BLK-1` + `R-BLK-2`) added after DNS on a shared IP
        // alongside a newer unblocked domain. Connect must record both `blk1.example` and
        // `blk2.example` (excluding `innocent-multi.example`), and deleting `R-BLK-1` must
        // preserve the block filter with `["blk2.example"]`.
        let multi_blk_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 30));
        let _ = send_dns(&engine_g, gp1.pid, "blk2.example", &[multi_blk_ip], now_ms + 400);
        let _ = send_dns(&engine_g, gp1.pid, "blk1.example", &[multi_blk_ip], now_ms + 500);
        let _ = send_dns(
            &engine_g,
            gp1.pid,
            "innocent-multi.example",
            &[multi_blk_ip],
            now_ms + 600,
        );
        engine_g
            .upsert_policy_rule(&mk_net_rule(
                "R-BLK-1",
                RuleScope::NetworkBlock,
                "blk1.example",
                now_ms + 605,
            ))
            .expect("upsert R-BLK-1");
        engine_g
            .upsert_policy_rule(&mk_net_rule(
                "R-BLK-2",
                RuleScope::NetworkBlock,
                "blk2.example",
                now_ms + 606,
            ))
            .expect("upsert R-BLK-2");
        assert!(!engine_g.has_active_wfp_filter(exe_g, Some(multi_blk_ip), false));

        send_connect(&engine_g, gp1.pid, multi_blk_ip, None, now_ms + 610);
        assert_domain_policy_hints(
            &engine_g,
            exe_g,
            multi_blk_ip,
            &["blk1.example", "blk2.example"],
            "multi-domain blocked connect must retain all domain-specific blocked hints and skip innocent domains",
        );
        engine_g
            .delete_policy_rule("R-BLK-1")
            .expect("delete R-BLK-1");
        assert!(
            engine_g.has_active_wfp_filter(exe_g, Some(multi_blk_ip), false),
            "deleting R-BLK-1 must preserve DomainPolicy Block while R-BLK-2 remains active"
        );
        assert_domain_policy_hints(&engine_g, exe_g, multi_blk_ip, &["blk2.example"], "");
        engine_g
            .delete_policy_rule("R-BLK-2")
            .expect("delete R-BLK-2");
        assert!(!engine_g.has_active_wfp_filter(exe_g, Some(multi_blk_ip), false));

        // Part G4: Wildcard-IP NetworkBlock (`203.0.113.*`) with an unblocked domain must also
        // stay untagged (`domain_hints: []`) instead of tagging the wildcard or unblocked domain.
        let wc_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 25));
        let _ = send_dns(&engine_g, gp1.pid, "innocent-wc.example", &[wc_ip], now_ms + 700);
        engine_g
            .upsert_policy_rule(&mk_net_rule(
                "R-WC-BLK",
                RuleScope::NetworkBlock,
                "203.0.113.*",
                now_ms + 705,
            ))
            .expect("upsert wildcard-IP block");
        send_connect(
            &engine_g,
            gp1.pid,
            wc_ip,
            Some("innocent-wc.example"),
            now_ms + 710,
        );
        assert_domain_policy_hints(
            &engine_g,
            exe_g,
            wc_ip,
            &[],
            "wildcard-IP static block must not pollute domain_hints",
        );
        engine_g
            .delete_policy_rule("R-WC-BLK")
            .expect("delete wildcard-IP block");
        assert!(!engine_g.has_active_wfp_filter(exe_g, Some(wc_ip), false));

        // Part H: `AllowPermanent` on ambiguous (`process_instance_id: None`,
        // `candidate_instance_ids`) alerts with multiple shared-IP domains.
        let gp2 = ProcessIdentity::new(9702, (now_ms as u64 + 11_644_473_600_000) * 10_000);
        send_process_start(&engine_g, gp2, exe_g);
        let ambig_clean_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 40));
        let _ = send_dns(&engine_g, gp1.pid, "ambig-a.example", &[ambig_clean_ip], now_ms + 1_000);
        let _ = send_dns(&engine_g, gp2.pid, "ambig-b.example", &[ambig_clean_ip], now_ms + 1_010);
        let ambig_clean_alert = make_pending_net_alert(
            "AL-P3-46A-AMBIG-CLEAN",
            now_ms + 1_020,
            "LEDR-NET-HIGH-RISK-PATH",
            "Ambiguous multi-domain alert",
            None,
            serde_json::json!({
                "attribution": "app_level_ambiguous",
                "candidate_instance_ids": [gp1.instance_id(), gp2.instance_id()],
                "exe_path": exe_g,
                "dst_ip": ambig_clean_ip.to_string(),
                "domain_hint": serde_json::Value::Null,
                "sha256": sha,
            }),
        );
        store_g
            .record_alert(&ambig_clean_alert)
            .expect("record ambiguous clean alert");
        engine_g
            .resolve_alert(
                &ambig_clean_alert.alert_id,
                ledr_proto::AlertDecision::AllowPermanent {
                    use_signer_if_available: false,
                    allow_dest: Some("ambig-a.example".to_string()),
                },
            )
            .expect("AllowPermanent on ambiguous alert");
        assert!(engine_g.has_active_wfp_filter(exe_g, Some(ambig_clean_ip), true));
        assert_domain_policy_hints(
            &engine_g,
            exe_g,
            ambig_clean_ip,
            &["ambig-a.example", "ambig-b.example"],
            "AllowPermanent on ambiguous alert must propagate all candidate_instance_ids shared-IP hints",
        );
        // Blocking the sibling hint `ambig-b.example` must immediately revoke the Permit.
        engine_g
            .upsert_policy_rule(&mk_net_rule(
                "R-BLK-AMBIG-B",
                RuleScope::NetworkBlock,
                "ambig-b.example",
                now_ms + 1_030,
            ))
            .expect("upsert block for ambig-b.example");
        assert!(
            !engine_g.has_active_wfp_filter(exe_g, Some(ambig_clean_ip), true),
            "blocking sibling candidate domain must revoke ambiguous AllowPermanent Permit"
        );
        engine_g
            .delete_policy_rule("R-BLK-AMBIG-B")
            .expect("cleanup R-BLK-AMBIG-B");

        // Part H2: Exe-level deny-overrides-allow suppression on an ambiguous alert when an
        // exited third instance (`gp3`, absent from `candidate_instance_ids`) resolved a
        // blocked domain on the same shared IP.
        let ambig_deny_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 41));
        let gp3 = ProcessIdentity::new(9703, (now_ms as u64 + 11_644_473_600_000) * 10_000);
        send_process_start(&engine_g, gp3, exe_g);
        let _ = send_dns(&engine_g, gp3.pid, "ambig-evil.example", &[ambig_deny_ip], now_ms + 1_100);
        send_process_stop(
            &engine_g,
            gp3.pid,
            ((now_ms + 1_110) as u64 + 11_644_473_600_000) * 10_000,
        );
        engine_g
            .upsert_policy_rule(&mk_net_rule(
                "R-BLK-AMBIG-EVIL",
                RuleScope::NetworkBlock,
                "ambig-evil.example",
                now_ms + 1_115,
            ))
            .expect("upsert R-BLK-AMBIG-EVIL");
        let _ = send_dns(&engine_g, gp1.pid, "ambig-good1.example", &[ambig_deny_ip], now_ms + 1_120);
        let _ = send_dns(&engine_g, gp2.pid, "ambig-good2.example", &[ambig_deny_ip], now_ms + 1_130);
        assert!(!engine_g.has_active_wfp_filter(exe_g, Some(ambig_deny_ip), false));
        let ambig_deny_alert = make_pending_net_alert(
            "AL-P3-46A-AMBIG-DENY",
            now_ms + 1_140,
            "LEDR-NET-HIGH-RISK-PATH",
            "Ambiguous deny-override alert",
            None,
            serde_json::json!({
                "attribution": "app_level_ambiguous",
                "candidate_instance_ids": [gp1.instance_id(), gp2.instance_id()],
                "exe_path": exe_g,
                "dst_ip": ambig_deny_ip.to_string(),
                "domain_hint": serde_json::Value::Null,
                "sha256": sha,
            }),
        );
        store_g
            .record_alert(&ambig_deny_alert)
            .expect("record ambiguous deny alert");
        engine_g
            .resolve_alert(
                &ambig_deny_alert.alert_id,
                ledr_proto::AlertDecision::AllowPermanent {
                    use_signer_if_available: false,
                    allow_dest: Some("ambig-good1.example".to_string()),
                },
            )
            .expect("AllowPermanent succeeds saving rule even when IP Permit is suppressed");
        assert!(
            !engine_g.has_active_wfp_filter(exe_g, Some(ambig_deny_ip), true),
            "ambiguous AllowPermanent must suppress IP Permit when exe-wide DNS history has blocked ambig-evil.example"
        );
        engine_g
            .delete_policy_rule("R-BLK-AMBIG-EVIL")
            .expect("cleanup R-BLK-AMBIG-EVIL");

        // Part I: `handle_ambiguous_wfp_drop` with two live instances (`gp1`, `gp2`) and
        // multiple fresh shared-IP domains (timestamps >= now_ms + 3_000 so exited `gp3` is
        // outside the 1s exit window).
        let cidr_allow_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 50));
        let cidr_deny_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 51));
        let cidr_override_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 52));
        for (pid, dom, ip, ts) in [
            (gp1.pid, "cdn-1.example", cidr_allow_ip, now_ms + 3_000),
            (gp2.pid, "cdn-2.example", cidr_allow_ip, now_ms + 3_010),
            (gp1.pid, "cdn-ok.example", cidr_deny_ip, now_ms + 3_020),
            (gp2.pid, "i2-evil.example", cidr_deny_ip, now_ms + 3_015),
            (gp1.pid, "ov-blk1.example", cidr_override_ip, now_ms + 3_030),
            (gp2.pid, "ov-blk2.example", cidr_override_ip, now_ms + 3_035),
        ] {
            let _ = send_dns(&engine_g, pid, dom, &[ip], ts);
        }
        engine_g
            .upsert_policy_rule(&mk_net_rule(
                "R-CIDR-ALLOW-I",
                RuleScope::NetworkAllow,
                "198.51.100.48/29",
                now_ms + 3_040,
            ))
            .expect("upsert CIDR allow for Part I");
        assert!(!engine_g.has_active_wfp_filter(exe_g, Some(cidr_allow_ip), true));
        assert!(!engine_g.has_active_wfp_filter(exe_g, Some(cidr_deny_ip), true));
        assert!(!engine_g.has_active_wfp_filter(exe_g, Some(cidr_override_ip), true));

        let has_alert_for_ip = |ip: IpAddr, rule_id: Option<&str>| -> bool {
            let ip_s = ip.to_string();
            store_g
                .list_alerts(None, 100)
                .unwrap()
                .into_iter()
                .any(|a| {
                    rule_id.is_none_or(|rid| a.rule_id == rid)
                        && serde_json::from_str::<serde_json::Value>(&a.context_json)
                            .ok()
                            .and_then(|v| {
                                v.get("dst_ip")
                                    .and_then(|x| x.as_str())
                                    .map(|s| s == ip_s)
                            })
                            .unwrap_or(false)
                })
        };
        let mk_drop = |dst_ip: IpAddr, timestamp_ms: i64| {
            make_queued_drop(exe_g, dst_ip, timestamp_ms, 1)
        };

        // I1: CIDR allow materializes Permit carrying ALL fresh candidate domain hints.
        engine_g.handle_wfp_drop_event_now(&mk_drop(cidr_allow_ip, now_ms + 3_050));
        assert!(
            !has_alert_for_ip(cidr_allow_ip, None),
            "CIDR-allowed ambiguous drop must not emit an alert"
        );
        assert!(engine_g.has_active_wfp_filter(exe_g, Some(cidr_allow_ip), true));
        assert_domain_policy_hints(
            &engine_g,
            exe_g,
            cidr_allow_ip,
            &["cdn-2.example", "cdn-1.example"],
            "handle_ambiguous_wfp_drop CIDR allow must propagate all fresh candidate domain hints",
        );

        // I2a: CIDR allow overridden by fresh blocked candidate (`i2-evil.example` older than
        // `cdn-ok.example` but still < 60s) under active app block: denies Permit, avoids
        // pinning a sticky IP Block (`BUG_..._0003`), and emits `LEDR-NET-POLICY-BLOCK`.
        engine_g
            .upsert_policy_rule(&mk_net_rule(
                "R-BLK-I2",
                RuleScope::NetworkBlock,
                "i2-evil.example",
                now_ms + 3_055,
            ))
            .expect("upsert R-BLK-I2");
        engine_g.handle_wfp_drop_event_now(&mk_drop(cidr_deny_ip, now_ms + 3_060));
        assert!(
            !engine_g.has_active_wfp_filter(exe_g, Some(cidr_deny_ip), true),
            "fresh blocked candidate must suppress CIDR allow Permit (deny-overrides-allow)"
        );
        assert!(
            !engine_g.has_active_wfp_filter(exe_g, Some(cidr_deny_ip), false),
            "ambiguous drop under active app block with no conflicting IP Permit must not pin sticky IP Block"
        );
        assert!(has_alert_for_ip(cidr_deny_ip, Some("LEDR-NET-POLICY-BLOCK")));

        // I2b: When a conflicting live IP Permit DOES exist on `cidr_override_ip`, ambiguous
        // drop with TWO fresh blocked candidates replaces the Permit with a `DomainPolicy`
        // Block carrying BOTH blocked hints so deleting one rule keeps the block alive.
        engine_g.handle_wfp_drop_event_now(&mk_drop(cidr_override_ip, now_ms + 3_065));
        assert!(engine_g.has_active_wfp_filter(exe_g, Some(cidr_override_ip), true));
        store_g
            .upsert_rule(&mk_net_rule(
                "R-OV-BLK1",
                RuleScope::NetworkBlock,
                "ov-blk1.example",
                now_ms + 3_066,
            ))
            .expect("seed R-OV-BLK1");
        store_g
            .upsert_rule(&mk_net_rule(
                "R-OV-BLK2",
                RuleScope::NetworkBlock,
                "ov-blk2.example",
                now_ms + 3_067,
            ))
            .expect("seed R-OV-BLK2");
        engine_g.handle_wfp_drop_event_now(&mk_drop(cidr_override_ip, now_ms + 3_070));
        assert!(!engine_g.has_active_wfp_filter(exe_g, Some(cidr_override_ip), true));
        assert!(engine_g.has_active_wfp_filter(exe_g, Some(cidr_override_ip), false));
        assert_domain_policy_hints(
            &engine_g,
            exe_g,
            cidr_override_ip,
            &["ov-blk2.example", "ov-blk1.example"],
            "ambiguous drop replacing live Permit must merge all fresh domain-specific blocked hints",
        );
        engine_g
            .delete_policy_rule("R-OV-BLK1")
            .expect("delete R-OV-BLK1");
        assert!(
            engine_g.has_active_wfp_filter(exe_g, Some(cidr_override_ip), false),
            "deleting R-OV-BLK1 must keep block alive for ov-blk2.example"
        );
        assert_domain_policy_hints(&engine_g, exe_g, cidr_override_ip, &["ov-blk2.example"], "");
        engine_g
            .delete_policy_rule("R-OV-BLK2")
            .expect("delete R-OV-BLK2");
        assert!(!engine_g.has_active_wfp_filter(exe_g, Some(cidr_override_ip), false));

        // I3: Non-CIDR ambiguous drop:
        // - Live IP Permit + fresh allowed candidate alongside newer unallowed candidate
        //   suppresses false ambiguous drop alert.
        // - Without a live IP Permit, non-CIDR domain allow does NOT materialize a Permit and
        //   emits an ambiguous drop alert.
        // - With a live IP Permit AND a fresh blocked candidate, deny-overrides-allow prevents
        //   live-Permit suppression and emits an alert.
        let non_cidr_live_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 60));
        let non_cidr_noperm_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 61));
        engine_g
            .upsert_policy_rule(&mk_net_rule(
                "R-ALLOW-I3",
                RuleScope::NetworkAllow,
                "i3-allow.example",
                now_ms + 3_090,
            ))
            .expect("upsert R-ALLOW-I3");
        let _ = send_dns(&engine_g, gp1.pid, "i3-allow.example", &[non_cidr_live_ip], now_ms + 3_100);
        let _ = send_dns(&engine_g, gp2.pid, "i3-other.example", &[non_cidr_live_ip], now_ms + 3_110);
        assert!(engine_g.has_active_wfp_filter(exe_g, Some(non_cidr_live_ip), true));
        engine_g.handle_wfp_drop_event_now(&mk_drop(non_cidr_live_ip, now_ms + 3_120));
        assert!(
            !has_alert_for_ip(non_cidr_live_ip, None),
            "non-CIDR live IP Permit + allowed candidate must suppress false ambiguous drop alert"
        );

        let _ = send_dns(
            &engine_g,
            gp1.pid,
            "i3-noperm.example",
            &[non_cidr_noperm_ip],
            now_ms + 3_130,
        );
        engine_g
            .upsert_policy_rule(&mk_net_rule(
                "R-ALLOW-I3B",
                RuleScope::NetworkAllow,
                "i3-noperm.example",
                now_ms + 3_135,
            ))
            .expect("upsert R-ALLOW-I3B");
        assert!(!engine_g.has_active_wfp_filter(exe_g, Some(non_cidr_noperm_ip), true));
        engine_g.handle_wfp_drop_event_now(&mk_drop(non_cidr_noperm_ip, now_ms + 3_140));
        assert!(
            !engine_g.has_active_wfp_filter(exe_g, Some(non_cidr_noperm_ip), true),
            "non-CIDR ambiguous drop without live Permit must not install a Permit"
        );
        assert!(
            has_alert_for_ip(non_cidr_noperm_ip, Some("LEDR-NET-HIGH-RISK-PATH")),
            "non-CIDR ambiguous drop without live Permit must emit ambiguous alert"
        );

        // Seed a block rule for `i3-other.example` directly (leaving the live Permit intact)
        // to verify `cand_decision == BlockedByRule` disables live-Permit suppression.
        store_g
            .upsert_rule(&mk_net_rule(
                "R-BLK-I3-OTHER",
                RuleScope::NetworkBlock,
                "i3-other.example",
                now_ms + 3_145,
            ))
            .expect("seed R-BLK-I3-OTHER");
        engine_g.handle_wfp_drop_event_now(&mk_drop(non_cidr_live_ip, now_ms + 3_150));
        assert!(
            has_alert_for_ip(non_cidr_live_ip, Some("LEDR-NET-HIGH-RISK-PATH")),
            "fresh blocked candidate must prevent non-CIDR live-Permit suppression"
        );

        // I4: Ambiguous drop hitting a CIDR NetworkBlock: pure CIDR keeps `domain_hints: []`,
        // while hybrid CIDR + fresh domain block retains `["blk-ah.example"]` across CIDR deletion.
        let ambig_cidr_pure_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 80));
        let ambig_cidr_hybrid_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 81));
        for (pid, dom, ip, ts) in [
            (gp1.pid, "innocent-ap.example", ambig_cidr_pure_ip, now_ms + 3_200),
            (gp1.pid, "innocent-ah.example", ambig_cidr_hybrid_ip, now_ms + 3_220),
            (gp2.pid, "blk-ah.example", ambig_cidr_hybrid_ip, now_ms + 3_210),
        ] {
            let _ = send_dns(&engine_g, pid, dom, &[ip], ts);
        }
        engine_g
            .upsert_policy_rule(&mk_net_rule(
                "R-AMBIG-CIDR-BLK",
                RuleScope::NetworkBlock,
                "203.0.113.80/30",
                now_ms + 3_230,
            ))
            .expect("upsert R-AMBIG-CIDR-BLK");
        engine_g
            .upsert_policy_rule(&mk_net_rule(
                "R-AMBIG-DOM-BLK",
                RuleScope::NetworkBlock,
                "blk-ah.example",
                now_ms + 3_231,
            ))
            .expect("upsert R-AMBIG-DOM-BLK");
        engine_g.handle_wfp_drop_event_now(&mk_drop(ambig_cidr_pure_ip, now_ms + 3_250));
        assert_domain_policy_hints(
            &engine_g,
            exe_g,
            ambig_cidr_pure_ip,
            &[],
            "ambiguous pure CIDR block must leave domain_hints empty",
        );
        engine_g.handle_wfp_drop_event_now(&mk_drop(ambig_cidr_hybrid_ip, now_ms + 3_250));
        assert_domain_policy_hints(
            &engine_g,
            exe_g,
            ambig_cidr_hybrid_ip,
            &["blk-ah.example"],
            "ambiguous hybrid CIDR + domain block must retain fresh domain-specific blocked hint",
        );
        engine_g
            .delete_policy_rule("R-AMBIG-CIDR-BLK")
            .expect("delete R-AMBIG-CIDR-BLK");
        assert!(
            !engine_g.has_active_wfp_filter(exe_g, Some(ambig_cidr_pure_ip), false),
            "pure CIDR block must be removed when R-AMBIG-CIDR-BLK is deleted"
        );
        assert!(
            engine_g.has_active_wfp_filter(exe_g, Some(ambig_cidr_hybrid_ip), false),
            "hybrid block must survive R-AMBIG-CIDR-BLK deletion while R-AMBIG-DOM-BLK remains"
        );
        assert_domain_policy_hints(&engine_g, exe_g, ambig_cidr_hybrid_ip, &["blk-ah.example"], "");
        engine_g
            .delete_policy_rule("R-AMBIG-DOM-BLK")
            .expect("delete R-AMBIG-DOM-BLK");
        assert!(!engine_g.has_active_wfp_filter(exe_g, Some(ambig_cidr_hybrid_ip), false));

        // Part J: Existing `DomainPolicy` Block survives deletion of co-blocking CIDR or first
        // domain block when a post-DNS `NetworkBlock` rule matches an active DNS-history domain
        // on the same IP (`deploy_persisted_network_rules_with_baseline` +
        // `reconcile_persisted_rules_with_dns_context`).
        let post_cidr_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 100));
        let post_dom_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 101));
        engine_g
            .upsert_policy_rule(&mk_net_rule(
                "R-J-CIDR",
                RuleScope::NetworkBlock,
                "203.0.113.100/32",
                now_ms + 3_300,
            ))
            .expect("upsert R-J-CIDR");
        engine_g
            .upsert_policy_rule(&mk_net_rule(
                "R-J-BLK1",
                RuleScope::NetworkBlock,
                "j-first.example",
                now_ms + 3_301,
            ))
            .expect("upsert R-J-BLK1");
        for (dom, ip, ts) in [
            ("j-post.example", post_cidr_ip, now_ms + 3_305),
            ("j-first.example", post_dom_ip, now_ms + 3_306),
            ("j-second.example", post_dom_ip, now_ms + 3_307),
        ] {
            let _ = send_dns(&engine_g, gp1.pid, dom, &[ip], ts);
        }
        // Install untagged CIDR Block on `post_cidr_ip` (`domain_hints: []`); `post_dom_ip`
        // already has `domain_hints: ["j-first.example"]`.
        send_connect(&engine_g, gp1.pid, post_cidr_ip, None, now_ms + 3_310);
        assert_domain_policy_hints(&engine_g, exe_g, post_cidr_ip, &[], "");
        assert_domain_policy_hints(&engine_g, exe_g, post_dom_ip, &["j-first.example"], "");
        // Upsert post-DNS block rules -> existing Blocks immediately sync live DNS domains.
        engine_g
            .upsert_policy_rule(&mk_net_rule(
                "R-J-POST",
                RuleScope::NetworkBlock,
                "j-post.example",
                now_ms + 3_315,
            ))
            .expect("upsert R-J-POST");
        engine_g
            .upsert_policy_rule(&mk_net_rule(
                "R-J-BLK2",
                RuleScope::NetworkBlock,
                "j-second.example",
                now_ms + 3_316,
            ))
            .expect("upsert R-J-BLK2");
        assert_domain_policy_hints(&engine_g, exe_g, post_cidr_ip, &["j-post.example"], "");
        assert_domain_policy_hints(
            &engine_g,
            exe_g,
            post_dom_ip,
            &["j-first.example", "j-second.example"],
            "",
        );
        // Deleting R-J-CIDR and R-J-BLK1 MUST preserve both Blocks for `j-post.example` /
        // `j-second.example`.
        engine_g
            .delete_policy_rule("R-J-CIDR")
            .expect("delete R-J-CIDR");
        engine_g
            .delete_policy_rule("R-J-BLK1")
            .expect("delete R-J-BLK1");
        assert_domain_policy_hints(
            &engine_g,
            exe_g,
            post_cidr_ip,
            &["j-post.example"],
            "deleting co-blocking CIDR rule must preserve Block for post-DNS j-post.example",
        );
        assert_domain_policy_hints(
            &engine_g,
            exe_g,
            post_dom_ip,
            &["j-second.example"],
            "deleting first domain block must preserve Block for post-DNS j-second.example",
        );
        engine_g
            .delete_policy_rule("R-J-POST")
            .expect("cleanup R-J-POST");
        engine_g
            .delete_policy_rule("R-J-BLK2")
            .expect("cleanup R-J-BLK2");
        assert!(!engine_g.has_active_wfp_filter(exe_g, Some(post_cidr_ip), false));
        assert!(!engine_g.has_active_wfp_filter(exe_g, Some(post_dom_ip), false));

        // Part K: Shared-IP Permit co-hosted domain retention across DNS FIFO eviction (both
        // `prematerialize_domain_wfp_filters` and `evaluate_and_handle_outbound_connect`) AND
        // migrated-domain Permit hint pruning (preventing false revocation after migration).
        let store_k = LedrStore::open_in_memory().expect("open store_k");
        let defense_k = Arc::new(TestDefense::new(500));
        let engine_k = start_stopped_engine(
            store_k.clone(),
            DaemonConfig {
                outbound_firewall_enabled: true,
                wfp_drop_dns_grace_ms: 500,
                dns_history_capacity: 4,
                ..DaemonConfig::default()
            },
            defense_k.clone(),
            Arc::new(FixedShaInspector(sha.clone())),
        )
        .await;
        let exe_k = r"C:\Temp\permit_hygiene_app.exe";
        let kp1 = ProcessIdentity::new(9801, (now_ms as u64 + 11_644_473_600_000) * 10_000);
        send_process_start(&engine_k, kp1, exe_k);
        let mk_k_rule = |rule_id: &str, scope: RuleScope, target: &str, created_at_ms: i64| {
            make_net_rule(rule_id, scope, exe_k, &sha, target, created_at_ms)
        };

        // K4 first (while `has_domain_network_rules() == false`): CIDR Permit prunes migrated
        // domain immediately on DNS migration so later blocking it does NOT revoke CIDR Permit.
        let k_cidr_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 193));
        let k_mig_away = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200));
        engine_k
            .upsert_policy_rule(&mk_k_rule(
                "R-K4-CIDR",
                RuleScope::NetworkAllow,
                "198.51.100.192/29",
                now_ms + 4_000,
            ))
            .expect("upsert R-K4-CIDR");
        assert!(!engine_k.firewall.lock().unwrap().has_domain_network_rules());
        let _ = send_dns(&engine_k, kp1.pid, "cdn-mig.example", &[k_cidr_ip], now_ms + 4_005);
        send_connect(&engine_k, kp1.pid, k_cidr_ip, None, now_ms + 4_010);
        assert_domain_policy_hints(&engine_k, exe_k, k_cidr_ip, &["cdn-mig.example"], "");
        let _ = send_dns(&engine_k, kp1.pid, "cdn-mig.example", &[k_mig_away], now_ms + 4_020);
        assert_domain_policy_hints(
            &engine_k,
            exe_k,
            k_cidr_ip,
            &[],
            "migrated domain must be pruned from CIDR Permit even with no domain rules active",
        );
        engine_k
            .upsert_policy_rule(&mk_k_rule(
                "R-K4-BLK-MIG",
                RuleScope::NetworkBlock,
                "cdn-mig.example",
                now_ms + 4_025,
            ))
            .expect("upsert R-K4-BLK-MIG");
        assert!(
            engine_k.has_active_wfp_filter(exe_k, Some(k_cidr_ip), true),
            "blocking migrated cdn-mig.example must not falsely revoke CIDR Permit on old IP"
        );

        // K1: `prematerialize` propagates co-hosted `cohost1.example` onto Permit; after DNS
        // FIFO eviction (`dns_history_capacity = 4`), blocking `cohost1.example` still revokes it.
        let k1_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 171));
        let k2_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 172));
        let k3_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 173));
        engine_k
            .upsert_policy_rule(&mk_k_rule(
                "R-K1-ALLOW",
                RuleScope::NetworkAllow,
                "allow-k1.example",
                now_ms + 4_030,
            ))
            .expect("upsert R-K1-ALLOW");
        let _ = send_dns(&engine_k, kp1.pid, "cohost1.example", &[k1_ip], now_ms + 4_035);
        let _ = send_dns(&engine_k, kp1.pid, "allow-k1.example", &[k1_ip], now_ms + 4_040);
        assert_domain_policy_hints(
            &engine_k,
            exe_k,
            k1_ip,
            &["allow-k1.example", "cohost1.example"],
            "prematerialize must retain co-hosted shared-IP domains on DomainPolicy Permit",
        );

        // K2: `evaluate_and_handle_outbound_connect` (rule added after DNS) also propagates
        // co-hosted unallowed `cohost2.example` onto Permit.
        let _ = send_dns(&engine_k, kp1.pid, "cohost2.example", &[k2_ip], now_ms + 4_045);
        let _ = send_dns(&engine_k, kp1.pid, "allow-k2.example", &[k2_ip], now_ms + 4_046);
        engine_k
            .upsert_policy_rule(&mk_k_rule(
                "R-K2-ALLOW",
                RuleScope::NetworkAllow,
                "allow-k2.example",
                now_ms + 4_050,
            ))
            .expect("upsert R-K2-ALLOW");
        assert!(!engine_k.has_active_wfp_filter(exe_k, Some(k2_ip), true));
        send_connect(&engine_k, kp1.pid, k2_ip, None, now_ms + 4_055);
        assert_domain_policy_hints(
            &engine_k,
            exe_k,
            k2_ip,
            &["allow-k2.example", "cohost2.example"],
            "outbound connect Permit must retain co-hosted shared-IP domains",
        );

        // Flood 6 unrelated DNS queries to completely evict `cohost1`/`cohost2` from
        // `ProcessDnsHistory` (`dns_history_capacity = 4`).
        for idx in 0..6u8 {
            let _ = send_dns(
                &engine_k,
                kp1.pid,
                &format!("evict-k-{idx}.example"),
                &[IpAddr::V4(Ipv4Addr::new(198, 51, 100, 210 + idx))],
                now_ms + 4_100 + idx as i64,
            );
        }
        engine_k
            .upsert_policy_rule(&mk_k_rule(
                "R-K1-BLK-COHOST",
                RuleScope::NetworkBlock,
                "cohost1.example",
                now_ms + 4_120,
            ))
            .expect("upsert R-K1-BLK-COHOST");
        engine_k
            .upsert_policy_rule(&mk_k_rule(
                "R-K2-BLK-COHOST",
                RuleScope::NetworkBlock,
                "cohost2.example",
                now_ms + 4_121,
            ))
            .expect("upsert R-K2-BLK-COHOST");
        assert!(
            !engine_k.has_active_wfp_filter(exe_k, Some(k1_ip), true),
            "blocking cohost1.example must revoke prematerialized Permit even after DNS FIFO eviction"
        );
        assert!(
            !engine_k.has_active_wfp_filter(exe_k, Some(k2_ip), true),
            "blocking cohost2.example must revoke connect-installed Permit even after DNS FIFO eviction"
        );

        // K3: Migrating a co-hosted domain off a multi-domain Permit prunes it so later
        // blocking that migrated domain preserves the remaining allowed domain's Permit.
        engine_k
            .upsert_policy_rule(&mk_k_rule(
                "R-K3-ALLOW",
                RuleScope::NetworkAllow,
                "allow-k3.example",
                now_ms + 4_130,
            ))
            .expect("upsert R-K3-ALLOW");
        let _ = send_dns(&engine_k, kp1.pid, "migrating-k3.example", &[k3_ip], now_ms + 4_135);
        let _ = send_dns(&engine_k, kp1.pid, "allow-k3.example", &[k3_ip], now_ms + 4_140);
        let _ = send_dns(
            &engine_k,
            kp1.pid,
            "migrating-k3.example",
            &[IpAddr::V4(Ipv4Addr::new(203, 0, 113, 205))],
            now_ms + 4_150,
        );
        assert_domain_policy_hints(&engine_k, exe_k, k3_ip, &["allow-k3.example"], "");
        engine_k
            .upsert_policy_rule(&mk_k_rule(
                "R-K3-BLK-MIG",
                RuleScope::NetworkBlock,
                "migrating-k3.example",
                now_ms + 4_155,
            ))
            .expect("upsert R-K3-BLK-MIG");
        assert!(
            engine_k.has_active_wfp_filter(exe_k, Some(k3_ip), true),
            "blocking migrated co-hosted domain must preserve allow-k3.example Permit"
        );

        // Part L:
        // - L1: `AllowOnce` on an ambiguous (`domain_hint: null`) `LEDR-NET-POLICY-BLOCK` alert
        //       where a shared-IP domain is blocked by persisted `NetworkBlock` must NOT lift
        //       the app-wide `Preemptive` block or mark candidates `AllowOnce`.
        // - L2: `resolve_effective_domain_candidates` drops stale sensor `raw_domain_hint`
        //       superseded by newer DNS migration (`latest_ts <= event_ts_ms`) while keeping
        //       pre-migration out-of-order hints (`event_ts_ms < latest_ts`).
        // - L3: `ProcessDnsHistory::domains_for_exe_ip` returns empty for empty `exe_key`.
        let l1_alert = store_g
            .list_alerts(None, 100)
            .unwrap()
            .into_iter()
            .find(|a| {
                a.rule_id == "LEDR-NET-POLICY-BLOCK"
                    && a.process_instance_id.is_none()
                    && a.context_json.contains(&cidr_deny_ip.to_string())
            })
            .expect("ambiguous LEDR-NET-POLICY-BLOCK alert from Part I2a");
        assert!(engine_g.has_active_wfp_filter(exe_g, None, false));
        assert!(!engine_g.has_active_wfp_filter(exe_g, Some(cidr_deny_ip), false));
        engine_g
            .resolve_alert(&l1_alert.alert_id, ledr_proto::AlertDecision::AllowOnce)
            .expect("AllowOnce resolves alert while keeping persisted block enforced");
        assert!(
            engine_g.has_active_wfp_filter(exe_g, None, false),
            "AllowOnce on ambiguous alert with active shared-IP NetworkBlock must NOT lift Preemptive app block"
        );
        assert!(
            !engine_g.firewall.lock().unwrap().is_once_allowed(&gp1.instance_id())
                && !engine_g.firewall.lock().unwrap().is_once_allowed(&gp2.instance_id()),
            "AllowOnce must NOT mark candidates once-allowed when shared-IP NetworkBlock matches"
        );

        // L2: Superseded raw sensor `domain_hint` dropped after migration (`t >= latest_ts`),
        //     preserved for out-of-order pre-migration connects (`t < latest_ts`).
        let l2_old_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 53));
        let l2_new_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 222));
        engine_g
            .upsert_policy_rule(&mk_net_rule(
                "R-L2-BLK-EVIL",
                RuleScope::NetworkBlock,
                "l2-mig-evil.example",
                now_ms + 4_500,
            ))
            .expect("upsert R-L2-BLK-EVIL");
        let _ = send_dns(&engine_g, gp1.pid, "l2-mig-evil.example", &[l2_old_ip], now_ms + 4_510);
        assert!(engine_g.has_active_wfp_filter(exe_g, Some(l2_old_ip), false));
        let _ = send_dns(&engine_g, gp1.pid, "l2-mig-evil.example", &[l2_new_ip], now_ms + 4_520);
        assert!(!engine_g.has_active_wfp_filter(exe_g, Some(l2_old_ip), false));
        assert!(
            engine_g
                .resolve_effective_domain_candidates(
                    Some(&gp1.instance_id()),
                    Some(exe_g),
                    l2_old_ip,
                    Some("l2-mig-evil.example"),
                    now_ms + 4_530,
                )
                .is_empty(),
            "post-migration sensor raw_domain_hint must be dropped"
        );
        assert_eq!(
            engine_g.resolve_effective_domain_candidates(
                Some(&gp1.instance_id()),
                Some(exe_g),
                l2_old_ip,
                Some("l2-mig-evil.example"),
                now_ms + 4_515,
            ),
            vec![("l2-mig-evil.example".to_string(), now_ms + 4_515)],
            "pre-migration out-of-order raw_domain_hint must still be preserved"
        );
        // Full connect to `l2_old_ip` (covered by `R-CIDR-ALLOW-I` 198.51.100.48/29) carrying
        // stale sensor hint `l2-mig-evil.example` must be allowed (Permit, not Block).
        send_connect(
            &engine_g,
            gp1.pid,
            l2_old_ip,
            Some("l2-mig-evil.example"),
            now_ms + 4_530,
        );
        assert!(
            !engine_g.has_active_wfp_filter(exe_g, Some(l2_old_ip), false),
            "stale sensor hint must not re-install retired DomainPolicy Block"
        );
        assert!(
            engine_g.has_active_wfp_filter(exe_g, Some(l2_old_ip), true),
            "CIDR allow must install Permit after dropping superseded sensor domain hint"
        );
        assert!(
            hist.domains_for_exe_ip("", shared_ip).is_empty(),
            "empty exe_key must never leak domains across executables"
        );

        // Part M:
        // - M1: Wildcard-IP `NetworkAllow` (`198.51.100.*`) with empty DNS history leaves
        //       `domain_hints: []` across connect, ambiguous drop, and `AllowPermanent`.
        // - M2: Engine-level `> 32` (`MAX_DOMAIN_HINTS_PER_FILTER`) domain-specific blocked
        //       hints on one shared IP stay strictly bounded at 32 via outbound connect.
        let wc_conn_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 231));
        let wc_ambig_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 232));
        let wc_perm_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 233));
        let wc_allow_alert = make_pending_net_alert(
            "AL-P3-46A-WC-ALLOW",
            now_ms + 5_000,
            "LEDR-NET-HIGH-RISK-PATH",
            "Wildcard IP AllowPermanent alert",
            Some(gp1.instance_id()),
            serde_json::json!({
                "exe_path": exe_g,
                "dst_ip": wc_perm_ip.to_string(),
                "domain_hint": serde_json::Value::Null,
                "sha256": sha,
            }),
        );
        store_g
            .record_alert(&wc_allow_alert)
            .expect("record wildcard allow alert");
        let wc_outcome = engine_g
            .resolve_alert_with_outcome(
                &wc_allow_alert.alert_id,
                ledr_proto::AlertDecision::AllowPermanent {
                    use_signer_if_available: false,
                    allow_dest: Some("198.51.100.*".to_string()),
                },
            )
            .expect("AllowPermanent wildcard-IP allow");
        assert_domain_policy_hints(
            &engine_g,
            exe_g,
            wc_perm_ip,
            &[],
            "AllowPermanent wildcard-IP allow with no DNS must leave domain_hints empty",
        );
        send_connect(&engine_g, gp1.pid, wc_conn_ip, None, now_ms + 5_010);
        assert_domain_policy_hints(
            &engine_g,
            exe_g,
            wc_conn_ip,
            &[],
            "outbound connect wildcard-IP allow with no DNS must leave domain_hints empty",
        );
        engine_g.handle_wfp_drop_event_now(&mk_drop(wc_ambig_ip, now_ms + 5_020));
        assert_domain_policy_hints(
            &engine_g,
            exe_g,
            wc_ambig_ip,
            &[],
            "ambiguous drop wildcard-IP allow with no DNS must leave domain_hints empty",
        );
        if let Some(wc_rid) = wc_outcome.saved_rule_id {
            engine_g
                .delete_policy_rule(&wc_rid)
                .expect("cleanup wildcard-IP allow rule");
        }

        // M2: Engine-level > 32 (`MAX_DOMAIN_HINTS_PER_FILTER`) domain-specific blocked hints
        //     on one shared IP via `evaluate_and_handle_outbound_connect` stays bounded at 32.
        let cap32_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 240));
        let gp4 = ProcessIdentity::new(9704, (now_ms as u64 + 11_644_473_600_000) * 10_000);
        send_process_start(&engine_g, gp4, exe_g);
        let pids = [gp1.pid, gp2.pid, gp4.pid];
        for idx in 0..36usize {
            let _ = send_dns(
                &engine_g,
                pids[idx / 12],
                &format!("m2-{idx:02}.cap32.example"),
                &[cap32_ip],
                now_ms + 5_100 + idx as i64,
            );
        }
        engine_g
            .upsert_policy_rule(&mk_net_rule(
                "R-M2-CAP32",
                RuleScope::NetworkBlock,
                "*.cap32.example",
                now_ms + 5_200,
            ))
            .expect("upsert R-M2-CAP32");
        send_connect(&engine_g, gp1.pid, cap32_ip, None, now_ms + 5_210);
        let Some(crate::firewall::WfpFilterOrigin::DomainPolicy { domain_hints }) = engine_g
            .firewall
            .lock()
            .unwrap()
            .filter_origin(exe_g, Some(cap32_ip))
            .cloned()
        else {
            panic!("expected DomainPolicy Block on cap32_ip");
        };
        assert_eq!(
            domain_hints.len(),
            crate::firewall::MAX_DOMAIN_HINTS_PER_FILTER,
            "engine-level multi-domain blocked connect must bound domain_hints at MAX_DOMAIN_HINTS_PER_FILTER"
        );
    });
}
