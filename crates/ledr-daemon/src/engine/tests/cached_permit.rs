use std::net::{IpAddr, Ipv4Addr};

/// `DAEMON-P3-49A` (`PRRT_kwDOVyjVyM65e5kL` + `AUD-P3-01` + `AUD-P3-02`):
/// Unit-integration verification of:
/// 1. `prematerialize_domain_wfp_filters` + unrelated `upsert_policy_rule` preserving the
///    authorizing hint on a shared-IP `DomainPolicy` Permit after `api.example` migrates;
/// 2. Cached old-IP `NetworkConnect` and `WfpDropEvent` (`on_wfp_drop_dequeued` single-PID
///    without grace parking, plus multi-PID `handle_ambiguous_wfp_drop`) passing via
///    `has_valid_live_domain_policy_permit` with 0 suspends and 0 alerts;
/// 3. Separate executable isolation (`SEC_0002`), unallowed co-hosted block vs post-migration
///    selective pruning, binary SHA-256 swap (`SEC_0001`), and `delete_policy_rule` revocation;
/// 4. Over-32 co-hosted domains (`MAX_DOMAIN_HINTS_PER_FILTER` overflow) never evicting the
///    authorizing hint via `partition_permit_hints` + `ensure_ip_permit_for_domain_hints_prioritized`.
#[test]
fn daemon_p3_49a_cached_ip_live_permit_revalidation_and_prioritized_hints() {
    use super::helpers::{
        make_net_rule, make_pending_net_alert, make_queued_drop, send_connect, send_dns,
        send_process_start, StubNotifier, TestDefense,
    };
    use super::{current_unix_ms, BinaryInspector, DaemonConfig, DaemonEngine};
    use crate::firewall::{WfpRuleManager, MAX_DOMAIN_HINTS_PER_FILTER};
    use ledr_proto::{ProcessIdentity, RuleScope};
    use ledr_rules::{BinaryIdentity, EarlyPruner, SigmaEngine};
    use ledr_store::LedrStore;
    use std::collections::{HashMap, VecDeque};
    use std::sync::{Arc, RwLock};

    struct MapShaInspector {
        shas: RwLock<HashMap<String, String>>,
    }
    impl MapShaInspector {
        fn new() -> Self {
            Self {
                shas: RwLock::new(HashMap::new()),
            }
        }
        fn set_sha(&self, exe: &str, sha: &str) {
            self.shas
                .write()
                .unwrap()
                .insert(WfpRuleManager::exe_key(exe), sha.to_string());
        }
    }
    impl super::BinaryInspector for MapShaInspector {
        fn inspect(&self, exe_path: &str) -> BinaryIdentity {
            let sha = self
                .shas
                .read()
                .unwrap()
                .get(&WfpRuleManager::exe_key(exe_path))
                .cloned();
            BinaryIdentity {
                exe_path: exe_path.to_string(),
                sha256: sha,
                authenticode: None,
            }
        }
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build rt");
    rt.block_on(async {
        let ps_exe = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
        let other_exe = r"C:\Users\alice\Downloads\other_app.exe";
        let unrelated_exe = r"C:\Tools\unrelated_app.exe";
        let sha_orig = "a".repeat(64);
        let sha_swapped = "b".repeat(64);
        let sha_other = "c".repeat(64);
        let sha_unrel = "d".repeat(64);

        let inspector = Arc::new(MapShaInspector::new());
        inspector.set_sha(ps_exe, &sha_orig);
        inspector.set_sha(other_exe, &sha_other);
        inspector.set_sha(unrelated_exe, &sha_unrel);

        let defense = Arc::new(TestDefense::new(1));
        let store = LedrStore::open_in_memory().expect("open store");
        let engine = DaemonEngine::start_with_dependencies(
            store.clone(),
            SigmaEngine::default(),
            EarlyPruner::default(),
            DaemonConfig {
                outbound_firewall_enabled: true,
                wfp_drop_dns_grace_ms: 500,
                dns_history_capacity: 64,
                ..DaemonConfig::default()
            },
            defense.clone(),
            Arc::new(StubNotifier),
            inspector.clone(),
        );

        let now_ms = current_unix_ms();
        let mk_rule = |id: &str, exe: &str, sha: &str, scope: RuleScope, target: &str, ts: i64| {
            make_net_rule(id, scope, exe, sha, target, ts)
        };

        let r_allow_api = mk_rule(
            "R-ALLOW-API",
            ps_exe,
            &sha_orig,
            RuleScope::NetworkAllow,
            "api.example",
            now_ms + 10,
        );
        engine
            .upsert_policy_rule(&r_allow_api)
            .expect("upsert R-ALLOW-API");

        let p1 = ProcessIdentity::new(9801, (now_ms as u64 + 11_644_473_600_000) * 10_000);
        send_process_start(&engine, p1, ps_exe);
        assert!(
            engine.has_active_wfp_filter(ps_exe, None, false),
            "pre-restricted PowerShell must have app-wide Preemptive WFP Block"
        );

        let ip1 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 180));
        let ip2 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 181));
        let ip3 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 182));

        // 1. Shared IP `ip1` (`other.example` unallowed + `api.example` allowed), then
        //    `api.example` migrates to `ip2`, followed by unrelated rule `upsert_policy_rule`.
        let _ = send_dns(&engine, p1.pid, "other.example", &[ip1], now_ms + 20);
        let _ = send_dns(&engine, p1.pid, "api.example", &[ip1], now_ms + 30);
        assert_eq!(
            engine
                .firewall
                .lock()
                .unwrap()
                .domain_policy_permit_hints(ps_exe, ip1),
            Some(vec!["api.example".to_string(), "other.example".to_string()])
        );

        let _ = send_dns(&engine, p1.pid, "api.example", &[ip2], now_ms + 40);
        assert!(engine.has_active_wfp_filter(ps_exe, Some(ip1), true));
        assert!(engine.has_active_wfp_filter(ps_exe, Some(ip2), true));
        assert_eq!(
            engine
                .firewall
                .lock()
                .unwrap()
                .domain_policy_permit_hints(ps_exe, ip1),
            Some(vec!["api.example".to_string(), "other.example".to_string()]),
            "migrating api.example must keep authorizing hint on shared-IP ip1 Permit"
        );

        let r_unrelated = mk_rule(
            "R-UNRELATED",
            unrelated_exe,
            &sha_unrel,
            RuleScope::NetworkAllow,
            "unrelated.example",
            now_ms + 50,
        );
        engine
            .upsert_policy_rule(&r_unrelated)
            .expect("upsert unrelated rule");
        assert!(
            engine.has_active_wfp_filter(ps_exe, Some(ip1), true),
            "unrelated rule save must preserve ip1 Permit after api.example migration"
        );
        assert!(engine.has_active_wfp_filter(ps_exe, Some(ip2), true));

        // 2. Cached old-IP `NetworkConnect` and `WfpDropEvent` (`on_wfp_drop_dequeued` single-
        //    PID and multi-PID ambiguous) must pass cleanly with 0 suspends and 0 alerts.
        send_connect(&engine, p1.pid, ip1, None, now_ms + 60);
        assert_eq!(defense.suspends(), 0);
        assert_eq!(engine.alerts_emitted(), 0);
        assert!(engine.has_active_wfp_filter(ps_exe, Some(ip1), true));

        let mk_drop = |exe: &str, ip: IpAddr, ts: i64| make_queued_drop(exe, ip, ts, 77);
        let mut pending = VecDeque::new();
        engine.on_wfp_drop_dequeued(mk_drop(ps_exe, ip1, now_ms + 70), &mut pending);
        assert!(
            pending.is_empty(),
            "live valid DomainPolicy Permit must bypass grace parking in on_wfp_drop_dequeued"
        );
        assert_eq!(defense.suspends(), 0);
        assert_eq!(engine.alerts_emitted(), 0);
        assert!(engine.has_active_wfp_filter(ps_exe, Some(ip1), true));

        // Multi-PID ambiguous drop for `ps_exe -> ip1` also stays silent.
        let p2 = ProcessIdentity::new(9802, (now_ms as u64 + 11_644_473_600_000) * 10_000);
        send_process_start(&engine, p2, ps_exe);
        engine.on_wfp_drop_dequeued(mk_drop(ps_exe, ip1, now_ms + 80), &mut pending);
        assert!(pending.is_empty());
        assert_eq!(defense.suspends(), 0);
        assert_eq!(engine.alerts_emitted(), 0);

        // Stale (> AMBIGUOUS_DNS_HISTORY_MAX_AGE_MS) multi-PID drop must still park so
        // multi-instance freshness symmetry is preserved across `on_wfp_drop_dequeued`,
        // `flush_ready_pending_wfp_drops`, and `handle_ambiguous_wfp_drop`.
        engine.on_wfp_drop_dequeued(
            mk_drop(
                ps_exe,
                ip1,
                now_ms + super::AMBIGUOUS_DNS_HISTORY_MAX_AGE_MS + 5_000,
            ),
            &mut pending,
        );
        assert_eq!(
            pending.len(),
            1,
            "stale >60s multi-PID drop must still park in grace queue"
        );
        pending.clear();

        // 3. Separate executable (`SEC_0002`) connecting to `ip1` must NOT inherit PowerShell's Permit.
        let p_other = ProcessIdentity::new(9803, (now_ms as u64 + 11_644_473_600_000) * 10_000);
        send_process_start(&engine, p_other, other_exe);
        send_connect(&engine, p_other.pid, ip1, None, now_ms + 90);
        assert_eq!(
            defense.suspends(),
            1,
            "different executable must be suspended when connecting to ip1 (SEC_0002)"
        );
        assert_eq!(engine.alerts_emitted(), 1);

        // 4. Blocking co-hosted `other.example` while still on `ip1` revokes `ip1` Permit
        //    immediately (`deny-overrides-allow`), and `has_valid_live_domain_policy_permit`
        //    rejects even a hypothetically stuck Permit.
        let r_blk_other = mk_rule(
            "R-BLK-OTHER",
            ps_exe,
            &sha_orig,
            RuleScope::NetworkBlock,
            "other.example",
            now_ms + 100,
        );
        engine
            .upsert_policy_rule(&r_blk_other)
            .expect("upsert R-BLK-OTHER");
        assert!(
            !engine.has_active_wfp_filter(ps_exe, Some(ip1), true),
            "blocking co-hosted other.example on ip1 must revoke ip1 Permit"
        );
        assert!(engine.has_active_wfp_filter(ps_exe, Some(ip2), true));

        // Defense-in-depth: even if a DomainPolicy Permit tagged ONLY `["api.example"]` were
        // stuck in `firewall` while `other.example` remains active in exe-wide DNS history and
        // blocked by `R-BLK-OTHER`, `has_valid_live_domain_policy_permit` MUST return `false`.
        {
            let mut fw = engine.firewall.lock().unwrap();
            fw.ensure_ip_permit_for_domain_hints_prioritized(
                ps_exe,
                ip1,
                &["api.example"],
                &[] as &[&str],
                &*defense,
            )
            .expect("inject stuck permit for defense-in-depth check");
        }
        let cur_rules_with_blk = store.list_network_rules().expect("list rules");
        let ps_identity = inspector.inspect(ps_exe);
        assert!(
            !engine.has_valid_live_domain_policy_permit(
                ps_exe,
                &ps_identity,
                ip1,
                &[],
                &cur_rules_with_blk,
                None,
            ),
            "stuck api.example-only Permit must be rejected when exe-wide DNS history has blocked other.example"
        );
        {
            let mut fw = engine.firewall.lock().unwrap();
            let _ = fw.remove_domain_policy_permit(ps_exe, ip1, &*defense);
        }

        // Remove `R-BLK-OTHER`, re-establish shared `ip1`, then migrate `other.example -> ip3`
        // before re-adding `R-BLK-OTHER`: `other.example` is selectively pruned so `ip1` survives!
        engine
            .delete_policy_rule("R-BLK-OTHER")
            .expect("delete R-BLK-OTHER");
        let _ = send_dns(&engine, p1.pid, "other.example", &[ip1], now_ms + 110);
        let _ = send_dns(&engine, p1.pid, "api.example", &[ip1], now_ms + 120);
        let _ = send_dns(&engine, p1.pid, "api.example", &[ip2], now_ms + 130);
        let _ = send_dns(&engine, p1.pid, "other.example", &[ip3], now_ms + 140);
        assert_eq!(
            engine
                .firewall
                .lock()
                .unwrap()
                .domain_policy_permit_hints(ps_exe, ip1),
            Some(vec!["api.example".to_string()]),
            "subsequent migration of other.example must selectively prune it from ip1 Permit"
        );
        engine
            .upsert_policy_rule(&r_blk_other)
            .expect("re-upsert R-BLK-OTHER after other.example migrated");
        assert!(
            engine.has_active_wfp_filter(ps_exe, Some(ip1), true),
            "blocking migrated other.example must preserve ip1 Permit"
        );
        let susp_before_post_mig = defense.suspends();
        let alerts_before_post_mig = engine.alerts_emitted();
        send_connect(&engine, p1.pid, ip1, None, now_ms + 150);
        assert_eq!(defense.suspends(), susp_before_post_mig);
        assert_eq!(engine.alerts_emitted(), alerts_before_post_mig);
        engine
            .delete_policy_rule("R-BLK-OTHER")
            .expect("cleanup R-BLK-OTHER");

        // 5. Binary SHA-256 swap (`SEC_0001`): connecting to cached `ip1` must fail live
        //    Permit re-validation, revoke stale Permits, suspend `p1`, and emit an alert.
        inspector.set_sha(ps_exe, &sha_swapped);
        let susp_before_swap = defense.suspends();
        let alerts_before_swap = engine.alerts_emitted();
        send_connect(&engine, p1.pid, ip1, None, now_ms + 160);
        assert!(
            !engine.has_active_wfp_filter(ps_exe, Some(ip1), true),
            "binary SHA-256 swap must revoke stale ip1 Permit (SEC_0001)"
        );
        assert_eq!(defense.suspends(), susp_before_swap + 1);
        assert_eq!(engine.alerts_emitted(), alerts_before_swap + 1);

        // Restore original SHA-256 and verify `delete_policy_rule` revokes Permits.
        inspector.set_sha(ps_exe, &sha_orig);
        let _ = send_dns(&engine, p2.pid, "api.example", &[ip1], now_ms + 170);
        let _ = send_dns(&engine, p2.pid, "api.example", &[ip2], now_ms + 180);
        assert!(engine.has_active_wfp_filter(ps_exe, Some(ip1), true));
        assert!(engine.has_active_wfp_filter(ps_exe, Some(ip2), true));
        engine
            .delete_policy_rule("R-ALLOW-API")
            .expect("delete R-ALLOW-API");
        assert!(!engine.has_active_wfp_filter(ps_exe, Some(ip1), true));
        assert!(!engine.has_active_wfp_filter(ps_exe, Some(ip2), true));

        // 6. > 32 co-hosted unallowed domains (`AUD-P3-02`): authorizing hint `api.example`
        //    must NEVER be FIFO-evicted during `prematerialize_domain_wfp_filters`, and
        //    subsequent unrelated reconciliation must preserve the Permit.
        engine
            .upsert_policy_rule(&r_allow_api)
            .expect("re-upsert R-ALLOW-API for cap32 test");
        let cap_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 190));
        let cap_ip2 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 191));
        let p3 = ProcessIdentity::new(9804, (now_ms as u64 + 11_644_473_600_000) * 10_000);
        send_process_start(&engine, p3, ps_exe);
        let pids = [p1.pid, p2.pid, p3.pid];
        for idx in 0..36usize {
            let _ = send_dns(
                &engine,
                pids[idx / 12],
                &format!("cohost-{idx:02}.shared.example"),
                &[cap_ip],
                now_ms + 200 + idx as i64,
            );
        }
        let _ = send_dns(&engine, p1.pid, "api.example", &[cap_ip], now_ms + 300);
        let cap_hints = engine
            .firewall
            .lock()
            .unwrap()
            .domain_policy_permit_hints(ps_exe, cap_ip)
            .expect("cap_ip DomainPolicy Permit must exist");
        assert_eq!(cap_hints.len(), MAX_DOMAIN_HINTS_PER_FILTER);
        assert!(
            cap_hints.iter().any(|h| h == "api.example"),
            "authorizing hint api.example must never be evicted under > 32 co-hosted domains"
        );
        // Migrate `api.example` off `cap_ip` to `cap_ip2` and save another unrelated rule ->
        // `cap_ip` Permit must survive!
        let _ = send_dns(&engine, p1.pid, "api.example", &[cap_ip2], now_ms + 310);
        let r_unrelated_2 = mk_rule(
            "R-UNRELATED-2",
            unrelated_exe,
            &sha_unrel,
            RuleScope::NetworkAllow,
            "unrelated-2.example",
            now_ms + 320,
        );
        engine
            .upsert_policy_rule(&r_unrelated_2)
            .expect("upsert second unrelated rule");
        assert!(
            engine.has_active_wfp_filter(ps_exe, Some(cap_ip), true),
            "cap_ip Permit must survive unrelated reconciliation after api.example migration under > 32 co-hosted domains"
        );

        // 7. Existing authorizing hint preservation across DNS-history eviction + subsequent
        //    merges under co-existing CIDR allow and second domain allow (`AUD-P3-02` deep):
        //    Evict `api.example` from `ProcessDnsHistory` (capacity = 64) via unrelated DNS
        //    churn, then merge new co-hosted domains via CIDR (`prematerialize`, `NetworkConnect`,
        //    multi-PID `handle_ambiguous_wfp_drop`) and via a second allow rule `keep.example`.
        let churn_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 250));
        for idx in 0..80usize {
            let _ = send_dns(
                &engine,
                p3.pid,
                &format!("churn-{idx:03}.noise.example"),
                &[churn_ip],
                now_ms + 400 + idx as i64,
            );
        }
        // 7a. Co-existing CIDR allow triggers `prematerialize`, `NetworkConnect`, and
        //     multi-PID `handle_ambiguous_wfp_drop` with `authorizing_hints = []` from DNS
        //     history alone; `extend_authorizing_hints_from_existing_permit` must protect
        //     existing `api.example` so deleting the CIDR rule leaves `cap_ip` Permit intact!
        let r_allow_cap_cidr = mk_rule(
            "R-ALLOW-CAP-CIDR",
            ps_exe,
            &sha_orig,
            RuleScope::NetworkAllow,
            "198.51.100.190/32",
            now_ms + 500,
        );
        engine
            .upsert_policy_rule(&r_allow_cap_cidr)
            .expect("upsert co-existing CIDR allow for cap_ip");
        let _ = send_dns(
            &engine,
            p2.pid,
            "cohost-cidr-90.shared.example",
            &[cap_ip],
            now_ms + 510,
        );
        send_connect(
            &engine,
            p2.pid,
            cap_ip,
            Some("cohost-cidr-91.shared.example"),
            now_ms + 520,
        );
        engine.on_wfp_drop_dequeued(mk_drop(ps_exe, cap_ip, now_ms + 530), &mut pending);
        assert!(pending.is_empty());
        let cap_hints_after_cidr = engine
            .firewall
            .lock()
            .unwrap()
            .domain_policy_permit_hints(ps_exe, cap_ip)
            .expect("cap_ip Permit must still exist after CIDR merges");
        assert_eq!(cap_hints_after_cidr.len(), MAX_DOMAIN_HINTS_PER_FILTER);
        assert!(
            cap_hints_after_cidr.iter().any(|h| h == "api.example"),
            "existing authorizing hint api.example must never be evicted by CIDR co-hosted merges"
        );
        engine
            .delete_policy_rule("R-ALLOW-CAP-CIDR")
            .expect("delete co-existing CIDR allow");
        assert!(
            engine.has_active_wfp_filter(ps_exe, Some(cap_ip), true),
            "deleting co-existing CIDR rule must preserve cap_ip Permit backed by retained api.example"
        );

        // 7b. Second domain allow (`keep.example`) arrives while `api.example` is absent from
        //     `ProcessDnsHistory`; BOTH `api.example` and `keep.example` stay protected so
        //     deleting `R-ALLOW-KEEP` preserves `cap_ip` Permit.
        let r_allow_keep = mk_rule(
            "R-ALLOW-KEEP",
            ps_exe,
            &sha_orig,
            RuleScope::NetworkAllow,
            "keep.example",
            now_ms + 540,
        );
        engine
            .upsert_policy_rule(&r_allow_keep)
            .expect("upsert R-ALLOW-KEEP");
        let _ = send_dns(&engine, p2.pid, "keep.example", &[cap_ip], now_ms + 550);
        let cap_hints_after_keep = engine
            .firewall
            .lock()
            .unwrap()
            .domain_policy_permit_hints(ps_exe, cap_ip)
            .expect("cap_ip Permit after keep.example");
        assert_eq!(cap_hints_after_keep.len(), MAX_DOMAIN_HINTS_PER_FILTER);
        assert!(
            cap_hints_after_keep.iter().any(|h| h == "api.example")
                && cap_hints_after_keep.iter().any(|h| h == "keep.example"),
            "both existing api.example and new keep.example must remain protected on cap_ip"
        );
        engine
            .delete_policy_rule("R-ALLOW-KEEP")
            .expect("delete R-ALLOW-KEEP");
        assert!(
            engine.has_active_wfp_filter(ps_exe, Some(cap_ip), true),
            "deleting R-ALLOW-KEEP must preserve cap_ip Permit backed by retained api.example"
        );

        // 7c. `AllowPermanent` (`resolve_alert`) on a full 32-hint Permit while `api.example`
        //     is absent from `ProcessDnsHistory`: CIDR allow with a new co-hosted hint must
        //     preserve existing `api.example` via `extend_authorizing_hints_from_existing_permit`.
        let allow_perm_alert = make_pending_net_alert(
            "AL-P3-49A-CAP-ALLOWPERM",
            now_ms + 560,
            "LEDR-NET-SCRIPT-INTERPRETER",
            "Full-32 AllowPermanent preservation check",
            Some(p2.instance_id()),
            serde_json::json!({
                "exe_path": ps_exe,
                "dst_ip": cap_ip.to_string(),
                "domain_hint": "cohost-allowperm-99.shared.example",
                "sha256": sha_orig,
            }),
        );
        store
            .record_alert(&allow_perm_alert)
            .expect("record AllowPermanent test alert");
        engine
            .resolve_alert(
                &allow_perm_alert.alert_id,
                ledr_proto::AlertDecision::AllowPermanent {
                    use_signer_if_available: false,
                    allow_dest: Some("198.51.100.190/32".to_string()),
                },
            )
            .expect("AllowPermanent CIDR on full 32-hint Permit");
        let cap_hints_after_ap = engine
            .firewall
            .lock()
            .unwrap()
            .domain_policy_permit_hints(ps_exe, cap_ip)
            .expect("cap_ip Permit after AllowPermanent");
        assert_eq!(cap_hints_after_ap.len(), MAX_DOMAIN_HINTS_PER_FILTER);
        assert!(
            cap_hints_after_ap.iter().any(|h| h == "api.example"),
            "AllowPermanent merge on full 32-hint Permit must never evict existing api.example"
        );
        assert!(
            cap_hints_after_ap
                .iter()
                .any(|h| h == "cohost-allowperm-99.shared.example"),
            "AllowPermanent must still record the new co-hosted hint by evicting an unprotected slot"
        );
        let ap_rule_id = store
            .list_network_rules()
            .expect("list rules")
            .into_iter()
            .find(|r| r.allowed_target.as_deref() == Some("198.51.100.190/32"))
            .expect("AllowPermanent CIDR rule persisted")
            .rule_id;
        engine
            .delete_policy_rule(&ap_rule_id)
            .expect("delete AllowPermanent CIDR rule");
        assert!(
            engine.has_active_wfp_filter(ps_exe, Some(cap_ip), true),
            "deleting AllowPermanent CIDR rule must preserve cap_ip Permit backed by retained api.example"
        );

        // 8. Wildcard `DomainPolicy` Permit hint (`*.wild.example`) multi-instance freshness:
        //    - Fresh allowed subdomain (`sub.wild.example`) migration passes `on_wfp_drop_dequeued`
        //      without grace parking and emits 0 alerts.
        //    - Stale allowed subdomain + fresh BLOCKED subdomain (`evil.wild.example`) must NOT
        //      falsely refresh `*.wild.example`, so multi-instance drop still parks.
        let wild_ip1 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 200));
        let wild_ip2 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 201));
        let wild_ip3 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 202));
        let r_allow_wild = mk_rule(
            "R-ALLOW-WILD",
            ps_exe,
            &sha_orig,
            RuleScope::NetworkAllow,
            "*.wild.example",
            now_ms + 600,
        );
        let r_blk_evil_wild = mk_rule(
            "R-BLK-EVIL-WILD",
            ps_exe,
            &sha_orig,
            RuleScope::NetworkBlock,
            "evil.wild.example",
            now_ms + 601,
        );
        engine
            .upsert_policy_rule(&r_allow_wild)
            .expect("upsert R-ALLOW-WILD");
        engine
            .upsert_policy_rule(&r_blk_evil_wild)
            .expect("upsert R-BLK-EVIL-WILD");
        {
            let mut fw = engine.firewall.lock().unwrap();
            fw.ensure_ip_permit_for_domain_hints_prioritized(
                ps_exe,
                wild_ip1,
                &["*.wild.example"],
                &[] as &[&str],
                &*defense,
            )
            .expect("install wildcard fallback DomainPolicy Permit");
        }
        let _ = send_dns(&engine, p2.pid, "sub.wild.example", &[wild_ip2], now_ms + 610);
        let alerts_before_wild = engine.alerts_emitted();
        engine.on_wfp_drop_dequeued(mk_drop(ps_exe, wild_ip1, now_ms + 620), &mut pending);
        assert!(
            pending.is_empty(),
            "fresh allowed subdomain matching *.wild.example must satisfy multi-instance freshness"
        );
        assert_eq!(engine.alerts_emitted(), alerts_before_wild);

        // Advance past `AMBIGUOUS_DNS_HISTORY_MAX_AGE_MS` so `sub.wild.example` is stale, then
        // record a fresh DNS query ONLY for blocked `evil.wild.example`: must STILL park!
        let stale_wild_ts = now_ms + 610 + super::AMBIGUOUS_DNS_HISTORY_MAX_AGE_MS + 5_000;
        let _ = send_dns(
            &engine,
            p2.pid,
            "evil.wild.example",
            &[wild_ip3],
            stale_wild_ts - 10,
        );
        engine.on_wfp_drop_dequeued(mk_drop(ps_exe, wild_ip1, stale_wild_ts), &mut pending);
        assert_eq!(
            pending.len(),
            1,
            "fresh blocked subdomain evil.wild.example must never refresh stale *.wild.example Permit"
        );
        pending.clear();

        // 9. Dual-stack (`A` + `AAAA`) and IPv4-mapped IPv6 (`::ffff:v4`) after IPv4-only
        //    migration: `has_valid_live_domain_policy_permit` and `has_fresh_domain_record_for_family`
        //    must canonicalize `::ffff:v4` and preserve independent v4/v6 freshness windows.
        let ds_v4_old = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 210));
        let ds_v4_old_mapped =
            IpAddr::V6(Ipv4Addr::new(198, 51, 100, 210).to_ipv6_mapped());
        let ds_v4_new = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 211));
        let ds_v6_old = IpAddr::V6(std::net::Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x210,
        ));
        let ds_t0 = now_ms + 700;
        let ds_t_v4_mig = ds_t0 + super::AMBIGUOUS_DNS_HISTORY_MAX_AGE_MS + 5_000;
        let _ = send_dns(&engine, p2.pid, "other.example", &[ds_v4_old, ds_v6_old], ds_t0);
        let _ = send_dns(&engine, p2.pid, "api.example", &[ds_v4_old, ds_v6_old], ds_t0);
        // Migrate ONLY IPv4 at `ds_t_v4_mig` (making `AAAA` at `ds_t0` stale > 60s while `A`
        // is fresh!).
        let _ = send_dns(&engine, p2.pid, "api.example", &[ds_v4_new], ds_t_v4_mig);
        let susp_before_ds = defense.suspends();
        let alerts_before_ds = engine.alerts_emitted();
        send_connect(&engine, p2.pid, ds_v4_old_mapped, None, ds_t_v4_mig + 10);
        send_connect(&engine, p2.pid, ds_v6_old, None, ds_t_v4_mig + 15);
        assert_eq!(defense.suspends(), susp_before_ds);
        assert_eq!(engine.alerts_emitted(), alerts_before_ds);

        // Multi-instance drops at `ds_t_v4_mig + 20`: `::ffff:ds_v4_old` has fresh v4 migration
        // -> bypasses parking; `ds_v6_old` has stale > 60s v6 -> MUST still park!
        engine.on_wfp_drop_dequeued(
            mk_drop(ps_exe, ds_v4_old_mapped, ds_t_v4_mig + 20),
            &mut pending,
        );
        assert!(
            pending.is_empty(),
            "IPv4-mapped IPv6 drop with fresh IPv4 migration must bypass multi-instance parking"
        );
        assert_eq!(engine.alerts_emitted(), alerts_before_ds);

        engine.on_wfp_drop_dequeued(
            mk_drop(ps_exe, ds_v6_old, ds_t_v4_mig + 25),
            &mut pending,
        );
        assert_eq!(
            pending.len(),
            1,
            "IPv6 drop with stale >60s AAAA must still park even after fresh IPv4-only migration"
        );
        pending.clear();

        engine.shutdown_and_flush().await.expect("shutdown");
    });
}
