use super::*;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use ledr_proto::{ActiveDefenseController, AllowlistRuleRecord, ProcessIdentity, RuleScope};
use ledr_rules::BinaryIdentity;

use crate::engine::BinaryInspector;

struct StubInspector(String);

impl BinaryInspector for StubInspector {
    fn inspect(&self, exe_path: &str) -> BinaryIdentity {
        BinaryIdentity {
            exe_path: exe_path.to_string(),
            sha256: Some(self.0.clone()),
            authenticode: None,
        }
    }
}

#[derive(Default)]
struct StubDefense {
    next_handle: AtomicU64,
    removed: Mutex<Vec<u64>>,
    fail_exes: Mutex<Vec<String>>,
    fail_removes: Mutex<bool>,
}

impl StubDefense {
    fn new() -> Self {
        Self {
            next_handle: AtomicU64::new(1),
            ..Self::default()
        }
    }

    fn set_fail_removes(&self, fail: bool) {
        *self.fail_removes.lock().expect("lock fail_removes") = fail;
    }

    fn add_fail_exe(&self, pat: &str) {
        self.fail_exes
            .lock()
            .expect("lock fail_exes")
            .push(pat.to_string());
    }
}

fn make_network_rule(
    rule_id: &str,
    scope: RuleScope,
    exe_path: &str,
    sha256: Option<&str>,
    allowed_target: Option<&str>,
    created_at_ms: i64,
) -> AllowlistRuleRecord {
    AllowlistRuleRecord {
        rule_id: rule_id.to_string(),
        scope,
        exe_path_pattern: exe_path.to_string(),
        sha256: sha256.map(str::to_string),
        signer_subject: None,
        root_thumbprint: None,
        allowed_target: allowed_target.map(str::to_string),
        created_at_ms,
        created_by: "test".to_string(),
    }
}

fn str_vec(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_string()).collect()
}

fn domain_policy_origin(hints: &[&str]) -> WfpFilterOrigin {
    WfpFilterOrigin::DomainPolicy {
        domain_hints: str_vec(hints),
    }
}

impl ActiveDefenseController for StubDefense {
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
        _allow: bool,
    ) -> Result<u64, String> {
        let s = exe_path.to_string_lossy().to_ascii_lowercase();
        if self
            .fail_exes
            .lock()
            .expect("lock fail_exes")
            .iter()
            .any(|pat| s.contains(pat))
        {
            return Err(format!("mock WFP add failure for {s}"));
        }
        Ok(self.next_handle.fetch_add(1, Ordering::Relaxed))
    }
    fn remove_wfp_rule(&self, filter_id: u64) -> Result<(), String> {
        if *self.fail_removes.lock().expect("lock fail_removes") {
            return Err(format!("mock WFP remove failure for {filter_id}"));
        }
        self.removed.lock().expect("lock removed").push(filter_id);
        Ok(())
    }
}

#[test]
fn firewall_register_preemptive_block_respects_active_allow_once() {
    let mut fw = WfpRuleManager::new();
    let defense = StubDefense::new();
    let ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    fw.mark_once_allowed("100:1", ps);
    let h = defense.add_wfp_app_rule(Path::new(ps), None, false).unwrap();
    assert!(!fw.register_preemptive_block(ps, h, &defense));
    assert!(!fw.has_any_app_filter(ps));
    assert_eq!(*defense.removed.lock().unwrap(), vec![h]);
}

#[test]
fn firewall_discard_obsolete_preemptive_block_retains_handle_on_remove_failure() {
    let mut fw = WfpRuleManager::new();
    let defense = StubDefense::new();
    let exe = r"C:\Users\Alice\Downloads\obsolete_race.exe";

    // 1. Clean removal leaves nothing tracked.
    let h1 = defense
        .add_wfp_app_rule(Path::new(exe), None, false)
        .unwrap();
    assert!(fw.discard_obsolete_preemptive_block(exe, h1, &defense));
    assert_eq!(fw.active_filter_count(), 0);
    assert_eq!(*defense.removed.lock().unwrap(), vec![h1]);

    // 2. Transient remove failure on vacant slot retains handle as Preemptive for retry.
    defense.set_fail_removes(true);
    let h2 = defense
        .add_wfp_app_rule(Path::new(exe), None, false)
        .unwrap();
    assert!(!fw.discard_obsolete_preemptive_block(exe, h2, &defense));
    assert!(fw.has_active_filter(exe, None, false));
    assert_eq!(
        fw.filter_origin(exe, None),
        Some(&WfpFilterOrigin::Preemptive)
    );
    assert_eq!(fw.active_app_block(exe), Some((h2, WfpFilterOrigin::Preemptive)));

    // Subsequent cleanup retries and clears the retained handle once BFE recovers.
    defense.set_fail_removes(false);
    assert!(fw.remove_preemptive_block_if_unused(exe, &defense));
    assert!(!fw.has_any_app_filter(exe));
    assert_eq!(*defense.removed.lock().unwrap(), vec![h1, h2]);

    // 3. Remove failure when another filter already occupies the slot must NOT clobber it.
    let policy_exe = r"C:\Users\Alice\Downloads\occupied_slot.exe";
    let inspector = StubInspector("b".repeat(64));
    let report = fw.reconcile_persisted_rules(
        &[make_network_rule(
            "R-OCC",
            RuleScope::NetworkBlock,
            policy_exe,
            None,
            None,
            1,
        )],
        &[],
        &inspector,
        &defense,
    );
    assert_eq!(report.applied, 1);
    let existing = fw.active_app_block(policy_exe).expect("policy block");
    assert_eq!(existing.1, WfpFilterOrigin::PersistedPolicy);

    defense.set_fail_removes(true);
    let h3 = defense
        .add_wfp_app_rule(Path::new(policy_exe), None, false)
        .unwrap();
    assert!(!fw.discard_obsolete_preemptive_block(policy_exe, h3, &defense));
    assert_eq!(fw.active_app_block(policy_exe), Some(existing));
}

#[test]
fn firewall_sweep_unused_preemptive_blocks_fast_path_and_protections() {
    let mut fw = WfpRuleManager::new();
    let defense = StubDefense::new();
    let inspector = StubInspector("c".repeat(64));

    // 1. Empty manager hits 0-candidate fast path without invoking `is_exe_active`.
    let mut probe_calls = 0usize;
    assert_eq!(
        fw.sweep_unused_preemptive_blocks(
            |_| {
                probe_calls += 1;
                false
            },
            &defense,
        ),
        0
    );
    assert_eq!(probe_calls, 0);

    // 2. Protected origins and states (PersistedPolicy, DomainPolicy, TransientContainment,
    //    startup-pinned Preemptive, alert-bound Preemptive) also hit 0-candidate fast path
    //    and are never removed even when no process is active.
    let startup_ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    let policy_exe = r"C:\Tools\policy_keep.exe";
    let domain_exe = r"C:\Tools\domain_keep.exe";
    let transient_exe = r"C:\Tools\transient_keep.exe";
    let bound_preempt_exe = r"C:\Users\Alice\Downloads\alert_bound.exe";
    let domain_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 44));

    fw.set_startup_preemptive_executables(&[startup_ps.to_string()]);
    let report = fw.reconcile_persisted_rules(
        &[make_network_rule(
            "R-SWEEP-KEEP",
            RuleScope::NetworkBlock,
            policy_exe,
            None,
            None,
            1,
        )],
        &[],
        &inspector,
        &defense,
    );
    assert_eq!(report.applied, 2); // startup_ps + policy_exe

    let _ = fw
        .ensure_domain_policy_block(domain_exe, domain_ip, "bad.example", &defense)
        .expect("domain block");
    let h_trans = defense
        .add_wfp_app_rule(Path::new(transient_exe), None, false)
        .unwrap();
    assert!(fw
        .register_transient_containment("ALT-TRANS", transient_exe, h_trans, &defense)
        .is_some());
    let h_bound = defense
        .add_wfp_app_rule(Path::new(bound_preempt_exe), None, false)
        .unwrap();
    assert!(fw.register_preemptive_block(bound_preempt_exe, h_bound, &defense));
    assert!(fw.bind_alert_to_app_block("ALT-PREEMPT", bound_preempt_exe));

    assert_eq!(
        fw.sweep_unused_preemptive_blocks(
            |_| {
                probe_calls += 1;
                false
            },
            &defense,
        ),
        0
    );
    assert_eq!(
        probe_calls, 0,
        "only non-sweepable filters installed must hit 0-candidate fast path"
    );
    assert_eq!(fw.active_filter_count(), 5);

    // 3. Live non-startup Preemptive filters that were NEVER queued for failed removal (including
    //    `evicted_live_exe`, simulating a still-running app evicted from `ProcessTable` under
    //    capacity pressure, `PRRT_kwDOVyjVyM66kWHQ`) must ALSO hit the O(1) 0-candidate fast path
    //    with zero `is_exe_active` probes and must NEVER be removed.
    let active_exe = r"C:\Users\Alice\Downloads\still_active.exe";
    let evicted_live_exe = r"C:\Users\Alice\Downloads\evicted_from_process_table_still_running.exe";
    let active_key = WfpRuleManager::exe_key(active_exe);

    let h_active = defense
        .add_wfp_app_rule(Path::new(active_exe), None, false)
        .unwrap();
    assert!(fw.register_preemptive_block(active_exe, h_active, &defense));
    let h_evicted_live = defense
        .add_wfp_app_rule(Path::new(evicted_live_exe), None, false)
        .unwrap();
    assert!(fw.register_preemptive_block(evicted_live_exe, h_evicted_live, &defense));

    assert_eq!(
        fw.sweep_unused_preemptive_blocks(
            |_| {
                probe_calls += 1;
                false
            },
            &defense,
        ),
        0
    );
    assert_eq!(
        probe_calls, 0,
        "live non-pending Preemptive blocks must hit O(1) fast path without probing process_table"
    );
    assert!(fw.has_active_filter(active_exe, None, false));
    assert!(fw.has_active_filter(evicted_live_exe, None, false));

    // 4. Queue two failed removals: one via `discard_obsolete_preemptive_block` and one via
    //    `remove_preemptive_block_if_unused`. Sweep probes ONLY those two pending handles and
    //    removes ONLY them—leaving `evicted_live_exe` (even though `is_exe_active` returns
    //    `false`), `active_exe`, and all protected filters untouched.
    let unused_exe = r"C:\Users\Alice\Downloads\orphaned_retained.exe";
    let stop_failed_exe = r"C:\Users\Alice\Downloads\stop_remove_failed.exe";
    let reclaimed_exe = r"C:\Users\Alice\Downloads\reclaimed_before_sweep.exe";

    let h_stop_failed = defense
        .add_wfp_app_rule(Path::new(stop_failed_exe), None, false)
        .unwrap();
    assert!(fw.register_preemptive_block(stop_failed_exe, h_stop_failed, &defense));

    defense.set_fail_removes(true);
    let h_unused = defense
        .add_wfp_app_rule(Path::new(unused_exe), None, false)
        .unwrap();
    assert!(!fw.discard_obsolete_preemptive_block(unused_exe, h_unused, &defense));
    assert!(!fw.remove_preemptive_block_if_unused(stop_failed_exe, &defense));
    let h_reclaimed = defense
        .add_wfp_app_rule(Path::new(reclaimed_exe), None, false)
        .unwrap();
    assert!(!fw.discard_obsolete_preemptive_block(reclaimed_exe, h_reclaimed, &defense));
    defense.set_fail_removes(false);

    // Reclaiming `reclaimed_exe` for a newly started process clears its pending removal so a
    // subsequent `ProcessTable` eviction (`is_exe_active == false`) cannot strip it.
    assert!(fw.has_pending_preemptive_removal(reclaimed_exe));
    assert!(fw.clear_pending_preemptive_removal(reclaimed_exe));
    assert!(!fw.has_pending_preemptive_removal(reclaimed_exe));

    let mut probed_keys = Vec::new();
    let removed = fw.sweep_unused_preemptive_blocks(
        |exe_key| {
            probed_keys.push(exe_key.to_string());
            exe_key == active_key
        },
        &defense,
    );
    assert_eq!(removed, 2);
    assert_eq!(
        probed_keys.len(),
        2,
        "sweep must only probe explicitly pending-removal handles"
    );
    assert!(!fw.has_any_app_filter(unused_exe));
    assert!(!fw.has_any_app_filter(stop_failed_exe));
    assert!(
        fw.has_active_filter(evicted_live_exe, None, false),
        "live Preemptive block evicted from ProcessTable must never be swept"
    );
    assert!(
        fw.has_active_filter(reclaimed_exe, None, false),
        "reclaimed Preemptive block must never be swept even when is_exe_active returns false"
    );
    assert!(fw.has_active_filter(active_exe, None, false));
    assert!(fw.has_active_filter(startup_ps, None, false));
    assert!(fw.has_active_filter(policy_exe, None, false));
    assert!(fw.has_active_filter(domain_exe, Some(domain_ip), false));
    assert!(fw.has_active_filter(transient_exe, None, false));
    assert!(fw.has_active_filter(bound_preempt_exe, None, false));
    let removed_handles = defense.removed.lock().unwrap().clone();
    assert_eq!(removed_handles.len(), 2);
    assert!(removed_handles.contains(&h_unused));
    assert!(removed_handles.contains(&h_stop_failed));

    // 5. Binding an alert to a pending-removal Preemptive filter clears its pending removal so
    //    periodic sweeps protect it while the alert is unresolved (and after unbind until a
    //    ProcessStop/TerminateAndBlock explicitly attempts removal).
    let alert_rebound_exe = r"C:\Users\Alice\Downloads\pending_then_bound.exe";
    defense.set_fail_removes(true);
    let h_alert_rebound = defense
        .add_wfp_app_rule(Path::new(alert_rebound_exe), None, false)
        .unwrap();
    assert!(!fw.discard_obsolete_preemptive_block(alert_rebound_exe, h_alert_rebound, &defense));
    defense.set_fail_removes(false);
    assert!(fw.has_pending_preemptive_removal(alert_rebound_exe));
    assert!(fw.bind_alert_to_app_block("ALT-REBOUND", alert_rebound_exe));
    assert!(!fw.has_pending_preemptive_removal(alert_rebound_exe));
    assert_eq!(
        fw.sweep_unused_preemptive_blocks(|_| false, &defense),
        0,
        "alert-bound Preemptive filter must not be swept"
    );
    assert!(fw.has_active_filter(alert_rebound_exe, None, false));
}

#[test]
fn firewall_sweep_unused_preemptive_blocks_backoff_throttles_warnings_and_recovers() {
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    struct WarnCounterSubscriber {
        warn_count: Arc<AtomicUsize>,
    }

    impl tracing::Subscriber for WarnCounterSubscriber {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            if *event.metadata().level() == tracing::Level::WARN {
                self.warn_count.fetch_add(1, Ordering::SeqCst);
            }
        }
        fn enter(&self, _span: &tracing::span::Id) {}
        fn exit(&self, _span: &tracing::span::Id) {}
    }

    let mut fw = WfpRuleManager::new();
    let defense = StubDefense::new();
    let exe = r"C:\Users\Alice\Downloads\persistent_bfe_err.exe";

    defense.set_fail_removes(true);
    let h = defense
        .add_wfp_app_rule(Path::new(exe), None, false)
        .unwrap();
    assert!(!fw.discard_obsolete_preemptive_block(exe, h, &defense));
    assert!(fw.has_active_filter(exe, None, false));

    let warn_count = Arc::new(AtomicUsize::new(0));
    let sub = WarnCounterSubscriber {
        warn_count: Arc::clone(&warn_count),
    };

    // Consecutive failures emit WARN only on powers of two (1, 2, 4, 8).
    let expected_warns = [1usize, 2, 2, 3, 3, 3, 3, 4];
    tracing::subscriber::with_default(sub, || {
        for (idx, expected) in expected_warns.iter().enumerate() {
            assert_eq!(fw.sweep_unused_preemptive_blocks(|_| false, &defense), 0);
            assert_eq!(
                warn_count.load(Ordering::SeqCst),
                *expected,
                "unexpected cumulative warning count after failure #{}",
                idx + 1
            );
            assert!(fw.has_active_filter(exe, None, false));
        }

        // Process reactivation clears pending removal so subsequent sweeps neither warn nor strip
        // the filter (even if later evicted from ProcessTable).
        assert_eq!(fw.sweep_unused_preemptive_blocks(|_| true, &defense), 0);
        assert_eq!(warn_count.load(Ordering::SeqCst), 4);
        assert!(!fw.has_pending_preemptive_removal(exe));
        assert_eq!(fw.sweep_unused_preemptive_blocks(|_| false, &defense), 0);
        assert_eq!(warn_count.load(Ordering::SeqCst), 4);
        assert!(fw.has_active_filter(exe, None, false));

        // When the relaunched process later exits and `remove_preemptive_block_if_unused` fails,
        // the handle is re-queued (1 WARN from ProcessStop failure) and backoff starts fresh at 1
        // on the next sweep failure (1 WARN -> cumulative 6).
        assert!(!fw.remove_preemptive_block_if_unused(exe, &defense));
        assert_eq!(warn_count.load(Ordering::SeqCst), 5);
        assert!(fw.has_pending_preemptive_removal(exe));
        assert_eq!(fw.sweep_unused_preemptive_blocks(|_| false, &defense), 0);
        assert_eq!(warn_count.load(Ordering::SeqCst), 6);

        // Once BFE recovers, sweep removes the filter with zero extra warnings.
        defense.set_fail_removes(false);
        assert_eq!(fw.sweep_unused_preemptive_blocks(|_| false, &defense), 1);
        assert_eq!(warn_count.load(Ordering::SeqCst), 6);
    });

    assert!(!fw.has_any_app_filter(exe));
    assert_eq!(*defense.removed.lock().unwrap(), vec![h]);

    // Subsequent sweep hits O(1) 0-candidate fast path (0 probe calls).
    let mut probe_calls = 0usize;
    assert_eq!(
        fw.sweep_unused_preemptive_blocks(
            |_| {
                probe_calls += 1;
                false
            },
            &defense,
        ),
        0
    );
    assert_eq!(probe_calls, 0);
}

#[test]
fn firewall_reconcile_distinguishes_startup_preemptive_and_policy_failures() {
    let mut fw = WfpRuleManager::new();
    let defense = StubDefense::new();
    let inspector = StubInspector("a".repeat(64));
    let startup_ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    let policy_app = r"C:\Tools\policy_app.exe";

    fw.set_startup_preemptive_executables(&[startup_ps.to_string()]);
    defense.add_fail_exe("powershell.exe");

    // Only startup-pinned interpreter fails -> has_policy_failures() MUST be false!
    let report1 = fw.reconcile_persisted_rules(
        &[make_network_rule(
            "R1",
            RuleScope::NetworkBlock,
            policy_app,
            None,
            None,
            1,
        )],
        &[],
        &inspector,
        &defense,
    );
    assert_eq!(report1.applied, 1);
    assert_eq!(report1.failed, 1);
    assert!(!report1.has_policy_failures());
    assert!(report1.policy_failure_summary().is_empty());

    // Removing R1 fails when remove_wfp_rule fails -> has_policy_failures() MUST be true!
    defense.set_fail_removes(true);
    let report2 = fw.reconcile_persisted_rules(&[], &[], &inspector, &defense);
    assert!(report2.has_policy_failures());
    assert!(report2.policy_failure_summary().contains("remove"));
    assert!(report2.policy_failure_summary().contains("policy_app.exe"));
}

#[test]
fn firewall_shared_ip_deny_suppresses_permit_and_revoke_permits_clears_all() {
    let mut fw = WfpRuleManager::new();
    let defense = StubDefense::new();
    let app = r"C:\Tools\shared_cdn.exe";
    let shared_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50));
    let other_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 51));

    fw.ensure_domain_policy_block(app, shared_ip, "blocked.example", &defense)
        .expect("domain block");
    let permit_res = fw
        .ensure_ip_permit_for_domain_rule(app, shared_ip, "allowed.example", &defense)
        .expect("shared ip check");
    assert_eq!(permit_res, None, "existing IP block must suppress domain permit");
    assert!(fw.has_active_filter(app, Some(shared_ip), false));
    assert!(!fw.has_active_filter(app, Some(shared_ip), true));

    let p_handle = fw
        .ensure_ip_permit_for_domain_rule(app, other_ip, "allowed.example", &defense)
        .expect("other ip permit");
    assert!(p_handle.is_some());
    assert!(fw.has_any_permit_filter_for_exe(app));
    let revoked = fw.revoke_permits_for_exe(app, &defense);
    assert_eq!(revoked, 1);
    assert!(!fw.has_any_permit_filter_for_exe(app));
    assert!(fw.has_active_filter(app, Some(shared_ip), false));
}

#[test]
fn firewall_reconcile_scoping_and_rollback_fidelity() {
    let mut fw = WfpRuleManager::new();
    let defense = StubDefense::new();
    let sha_a = "a".repeat(64);
    let inspector = StubInspector(sha_a.clone());

    // 1. Pre-existing failure on broken.exe + CIDR rule does NOT flip `has_domain_network_rules`.
    let broken_exe = r"C:\Tools\broken.exe";
    let healthy_exe = r"C:\Tools\healthy.exe";
    let cidr_exe = r"C:\Tools\cidr.exe";
    defense.add_fail_exe("broken.exe");

    let broken_rule = make_network_rule("R-broken", RuleScope::NetworkBlock, broken_exe, None, None, 1);
    let cidr_rule = make_network_rule(
        "R-cidr",
        RuleScope::NetworkAllow,
        cidr_exe,
        Some(&sha_a),
        Some("198.51.100.0/24"),
        2,
    );
    let r1 = fw.reconcile_persisted_rules(&[broken_rule.clone(), cidr_rule.clone()], &[], &inspector, &defense);
    assert!(!fw.has_domain_network_rules(), "CIDR rule must not count as domain rule");
    assert!(r1.failure_summary_for_rules(&[&broken_rule]).is_some());
    assert!(r1.failure_summary_for_rules(&[&cidr_rule]).is_none());

    // Subsequent unrelated healthy rule mutation ignores pre-existing `broken.exe` failure.
    let healthy_rule = make_network_rule("R-healthy", RuleScope::NetworkBlock, healthy_exe, None, None, 3);
    let r2 = fw.reconcile_persisted_rules(
        &[broken_rule.clone(), cidr_rule.clone(), healthy_rule.clone()],
        &[],
        &inspector,
        &defense,
    );
    assert!(
        r2.failure_summary_for_rules(&[&healthy_rule]).is_none(),
        "pre-existing unrelated failure must not fail healthy rule mutation"
    );
    assert!(
        r2.failure_summary_for_rules(&[&broken_rule]).is_some(),
        "repeated failure on affected rule must still surface via failure_summary_for_rules"
    );
    // Same exe, unrelated domain block rule must NOT be blocked by `broken_rule`'s app-wide failure.
    let same_exe_ads_block = make_network_rule(
        "R-broken-ads-block",
        RuleScope::NetworkBlock,
        broken_exe,
        None,
        Some("ads.example.com"),
        4,
    );
    let r2_dom = fw.reconcile_persisted_rules(
        &[
            broken_rule.clone(),
            cidr_rule.clone(),
            healthy_rule.clone(),
            same_exe_ads_block.clone(),
        ],
        &[],
        &inspector,
        &defense,
    );
    assert!(
        r2_dom
            .failure_summary_for_rules(&[&same_exe_ads_block])
            .is_none(),
        "unrelated pre-existing failure on same exe must NOT block domain rule mutation"
    );
    assert!(fw.has_active_filter(healthy_exe, None, false));

    // 2. Promotion / DomainPolicy remove rollback snapshots:
    //    Simulate `healthy_exe` having both a TransientContainment block bound to alert "AL-1"
    //    and a DomainPolicy IP block while removing `healthy_rule` fails on `remove_wfp_rule`.
    let transient_app = r"C:\Tools\transient.exe";
    let h_tr = defense.add_wfp_app_rule(Path::new(transient_app), None, false).unwrap();
    fw.register_transient_containment("AL-1", transient_app, h_tr, &defense);
    let dom_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77));
    fw.ensure_domain_policy_block(transient_app, dom_ip, "bad.example", &defense)
        .unwrap();
    let tr_rule = make_network_rule("R-tr-block", RuleScope::NetworkBlock, transient_app, None, None, 4);
    let dom_rule = make_network_rule(
        "R-dom-block",
        RuleScope::NetworkBlock,
        transient_app,
        None,
        Some("bad.example"),
        5,
    );

    // Reconcile succeeds: `TransientContainment` promoted to `PersistedPolicy` and `AL-1` unbound,
    // and `promoted_backups` records pre-promote snapshot.
    let r3 = fw.reconcile_persisted_rules(&[tr_rule.clone(), dom_rule], &[], &inspector, &defense);
    assert_eq!(fw.filter_origin(transient_app, None), Some(&WfpFilterOrigin::PersistedPolicy));
    assert!(!fw.is_alert_bound("AL-1"));
    assert_eq!(r3.promoted_backups.len(), 1);

    // Restoring promotion snapshot brings back TransientContainment + AL-1 binding.
    fw.restore_promoted_filter_states(&r3.promoted_backups);
    assert_eq!(
        fw.filter_origin(transient_app, None),
        Some(&WfpFilterOrigin::TransientContainment)
    );
    assert!(fw.is_alert_bound("AL-1"));

    // Removing `dom_rule` deletes `DomainPolicy` filter and captures `removed_domain_filters`;
    // rollback re-installs `DomainPolicy` filter into BFE + `WfpRuleManager`.
    let r4 = fw.reconcile_persisted_rules(&[], &[], &inspector, &defense);
    assert_eq!(r4.removed_domain_filters.len(), 1);
    assert!(!fw.has_active_filter(transient_app, Some(dom_ip), false));
    fw.restore_removed_domain_filters(&r4.removed_domain_filters, &defense);
    assert!(fw.has_active_filter(transient_app, Some(dom_ip), false));
    assert_eq!(
        fw.filter_origin(transient_app, Some(dom_ip)),
        Some(&domain_policy_origin(&["bad.example"]))
    );
}

/// `FIREWALL-P3-47A` (`#4`, `#1`; unit-boundary counterpart to integration test `DAEMON-P3-47`):
/// Shared-IP `DomainPolicy` filters retain a bounded,
/// normalized set of domain hints across reuse, prune migrated domains and sync active
/// blocking reasons on migration so final migration removes the block even after earlier
/// domains were evicted from DNS history FIFO, preserve dual-stack IPv6 blocks, enforce
/// multi-domain Permit deny-overrides-allow reconciliation, and restore multi-domain
/// `RemovedDomainFilterSnapshot` faithfully.
#[test]
fn firewall_p3_47a_domain_policy_hint_set_migration_cleanup_and_rollback_fidelity() {
    use std::net::Ipv6Addr;

    let mut fw = WfpRuleManager::new();
    let defense = StubDefense::new();
    let sha_d = "d".repeat(64);
    let inspector = StubInspector(sha_d.clone());

    let app = r"C:\Tools\shared_blk_app.exe";
    let shared_v4 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 88));
    let new_a_v4 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
    let new_b_v4 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11));
    let v6_a = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x88));

    // 1. Reusing a shared-IP DomainPolicy Block merges distinct normalized hints without
    //    creating duplicate BFE handles or duplicate hint entries.
    let h1 = fw
        .ensure_domain_policy_block(app, shared_v4, "A.Example.", &defense)
        .expect("block a.example");
    let h2 = fw
        .ensure_domain_policy_block(app, shared_v4, "b.example", &defense)
        .expect("block b.example");
    let h3 = fw
        .ensure_domain_policy_block(app, shared_v4, "a.example", &defense)
        .expect("dedup a.example");
    assert_eq!(h1, h2);
    assert_eq!(h1, h3);
    assert_eq!(
        fw.filter_origin(app, Some(shared_v4)),
        Some(&domain_policy_origin(&["a.example", "b.example"]))
    );

    // Dual-stack IPv6 block for `a.example` on a separate address family.
    fw.ensure_domain_policy_block(app, v6_a, "a.example", &defense)
        .expect("block a.example v6");

    // 2. `a.example` migrates off `shared_v4` while `b.example` still actively blocks it:
    //    `shared_v4` stays blocked with `domain_hints` synced to `["b.example"]`, and `v6_a`
    //    stays completely intact.
    let mut active_blocking: HashMap<IpAddr, Vec<String>> = HashMap::new();
    active_blocking.insert(shared_v4, str_vec(&["b.example"]));
    let mut superseded: HashSet<(IpAddr, String)> = HashSet::new();
    superseded.insert((shared_v4, "a.example".to_string()));
    let removed_step1 = fw.invalidate_stale_domain_blocks_for_query(
        app,
        "a.example",
        &[new_a_v4],
        &HashSet::new(),
        &active_blocking,
        &superseded,
        &defense,
    );
    assert_eq!(removed_step1, 0);
    assert!(fw.has_active_filter(app, Some(shared_v4), false));
    assert_eq!(
        fw.filter_origin(app, Some(shared_v4)),
        Some(&domain_policy_origin(&["b.example"]))
    );
    assert_eq!(
        fw.filter_origin(app, Some(v6_a)),
        Some(&domain_policy_origin(&["a.example"])),
        "IPv4 migration must not disturb IPv6 DomainPolicy Block"
    );

    // 3. Even after `a.example` is evicted from `latest_domain_by_exe` FIFO (so
    //    `superseded_pairs` is completely empty!), migrating `b.example` off `shared_v4`
    //    deterministically removes the retired `shared_v4` block while keeping `v6_a`.
    let removed_step2 = fw.invalidate_stale_domain_blocks_for_query(
        app,
        "b.example",
        &[new_b_v4],
        &HashSet::new(),
        &HashMap::new(),
        &HashSet::new(),
        &defense,
    );
    assert_eq!(removed_step2, 1);
    assert!(
        !fw.has_active_filter(app, Some(shared_v4), false),
        "shared_v4 block must be removed once final domain b.example migrates away"
    );
    assert!(
        fw.has_active_filter(app, Some(v6_a), false),
        "IPv6 block for a.example must remain unaffected by IPv4 migrations"
    );

    // 4. Even if `b.example` was NOT originally recorded on the filter before `a.example`
    //    migrated, syncing `active_blocking_domains_by_ip` during `a.example`'s migration
    //    transitions `domain_hints` to `["b.example"]` so `b.example`'s later migration still
    //    clears the filter with empty `superseded_pairs`.
    fw.ensure_domain_policy_block(app, shared_v4, "a.example", &defense)
        .expect("re-block a.example only");
    assert_eq!(
        fw.invalidate_stale_domain_blocks_for_query(
            app,
            "a.example",
            &[new_a_v4],
            &HashSet::new(),
            &active_blocking,
            &HashSet::new(),
            &defense,
        ),
        0
    );
    assert_eq!(
        fw.filter_origin(app, Some(shared_v4)),
        Some(&domain_policy_origin(&["b.example"]))
    );
    assert_eq!(
        fw.invalidate_stale_domain_blocks_for_query(
            app,
            "b.example",
            &[new_b_v4],
            &HashSet::new(),
            &HashMap::new(),
            &HashSet::new(),
            &defense,
        ),
        1
    );
    assert!(!fw.has_active_filter(app, Some(shared_v4), false));

    // 5. Hint set is strictly bounded by `MAX_DOMAIN_HINTS_PER_FILTER` (32).
    let cap_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99));
    for idx in 0..(MAX_DOMAIN_HINTS_PER_FILTER + 8) {
        fw.ensure_domain_policy_block(app, cap_ip, &format!("d{idx}.example"), &defense)
            .expect("bounded hint merge");
    }
    let Some(WfpFilterOrigin::DomainPolicy { domain_hints }) =
        fw.filter_origin(app, Some(cap_ip))
    else {
        panic!("expected DomainPolicy origin for cap_ip");
    };
    assert_eq!(domain_hints.len(), MAX_DOMAIN_HINTS_PER_FILTER);
    assert_eq!(domain_hints.first().map(String::as_str), Some("d8.example"));
    assert_eq!(
        domain_hints.last().map(String::as_str),
        Some("d39.example")
    );

    // 6. Multi-domain Permit accumulation, Block hint pruning, deny-overrides-allow removal,
    //    and `RemovedDomainFilterSnapshot` restore fidelity.
    let perm_app = r"C:\Tools\shared_perm_app.exe";
    let perm_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 55));
    let blk_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 56));
    let p_h1 = fw
        .ensure_ip_permit_for_domain_rule(perm_app, perm_ip, "good1.example", &defense)
        .expect("permit good1");
    let p_h2 = fw
        .ensure_ip_permit_for_domain_rule(perm_app, perm_ip, "good2.example", &defense)
        .expect("permit good2");
    assert_eq!(p_h1, p_h2);
    assert_eq!(
        fw.filter_origin(perm_app, Some(perm_ip)),
        Some(&domain_policy_origin(&["good1.example", "good2.example"]))
    );
    fw.ensure_domain_policy_block(perm_app, blk_ip, "blk1.example", &defense)
        .expect("blk1");
    fw.ensure_domain_policy_block(perm_app, blk_ip, "blk2.example", &defense)
        .expect("blk2");

    let allow_good1 = make_network_rule(
        "R-ALLOW-1",
        RuleScope::NetworkAllow,
        perm_app,
        Some(&sha_d),
        Some("good1.example"),
        1,
    );
    let block_blk2 = make_network_rule(
        "R-BLK-2",
        RuleScope::NetworkBlock,
        perm_app,
        Some(&sha_d),
        Some("blk2.example"),
        2,
    );
    // Reconcile with only `good1` allowed and only `blk2` blocked:
    // - Permit stays alive because `good1` is still allowed and neither is blocked.
    // - Block stays alive and prunes `blk1.example`, retaining only `["blk2.example"]`
    //   (with rollback backup capturing `["blk1.example", "blk2.example"]`).
    let rep_keep = fw.reconcile_persisted_rules(
        &[allow_good1.clone(), block_blk2.clone()],
        &[],
        &inspector,
        &defense,
    );
    assert!(fw.has_active_filter(perm_app, Some(perm_ip), true));
    assert!(fw.has_active_filter(perm_app, Some(blk_ip), false));
    assert_eq!(
        fw.filter_origin(perm_app, Some(blk_ip)),
        Some(&domain_policy_origin(&["blk2.example"]))
    );
    fw.restore_promoted_filter_states(&rep_keep.promoted_backups);
    assert_eq!(
        fw.filter_origin(perm_app, Some(blk_ip)),
        Some(&domain_policy_origin(&["blk1.example", "blk2.example"])),
        "rollback of reconciled Block hint pruning must restore original hint set"
    );

    // Adding a block for `good2.example` revokes the multi-domain Permit (deny-overrides-allow)
    // and captures all `domain_hints` in `RemovedDomainFilterSnapshot`.
    let block_good2 = make_network_rule(
        "R-BLK-GOOD2",
        RuleScope::NetworkBlock,
        perm_app,
        Some(&sha_d),
        Some("good2.example"),
        3,
    );
    let rep_revoke = fw.reconcile_persisted_rules(
        &[allow_good1, block_blk2, block_good2],
        &[],
        &inspector,
        &defense,
    );
    assert!(
        !fw.has_active_filter(perm_app, Some(perm_ip), true),
        "blocking any domain in Permit hint set must revoke shared-IP Permit"
    );
    let perm_snap = rep_revoke
        .removed_domain_filters
        .iter()
        .find(|s| s.remote_ip == perm_ip && s.allow)
        .expect("removed Permit snapshot");
    assert_eq!(perm_snap.domain_hints, str_vec(&["good1.example", "good2.example"]));

    // Restoring the snapshot reproduces the exact multi-domain hint vector.
    fw.restore_removed_domain_filters(std::slice::from_ref(perm_snap), &defense);
    assert_eq!(
        fw.filter_origin(perm_app, Some(perm_ip)),
        Some(&domain_policy_origin(&["good1.example", "good2.example"]))
    );

    // 7. Non-blocked query resolving to an IP whose previous blocking hints are ALL superseded
    //    must REMOVE the stale block filter instead of keeping it on `new_canon.contains(&ip)`
    //    and corrupting `domain_hints` to empty `[]`.
    fw.ensure_domain_policy_block(app, shared_v4, "a.example", &defense)
        .expect("install block for a.example");
    let mut sup_a: HashSet<(IpAddr, String)> = HashSet::new();
    sup_a.insert((shared_v4, "a.example".to_string()));
    let removed_on_allowed_query = fw.invalidate_stale_domain_blocks_for_query(
        app,
        "allowed.example",
        &[shared_v4],
        &HashSet::new(),
        &HashMap::new(),
        &sup_a,
        &defense,
    );
    assert_eq!(
        removed_on_allowed_query, 1,
        "non-blocked query resolving to IP with superseded block must remove stale block"
    );
    assert!(!fw.has_active_filter(app, Some(shared_v4), false));

    // 8. Hybrid CIDR + domain Block reconciliation: deleting the domain block while the CIDR
    //    block stays active prunes the deleted domain hint to `[]` while keeping the filter
    //    alive, and rollback restores the pre-prune hint set.
    let cidr_block = make_network_rule(
        "R-BLK-CIDR",
        RuleScope::NetworkBlock,
        perm_app,
        Some(&sha_d),
        Some("203.0.113.0/24"),
        4,
    );
    let rep_cidr_only = fw.reconcile_persisted_rules(
        std::slice::from_ref(&cidr_block),
        &[],
        &inspector,
        &defense,
    );
    assert!(fw.has_active_filter(perm_app, Some(blk_ip), false));
    assert_eq!(
        fw.filter_origin(perm_app, Some(blk_ip)),
        Some(&domain_policy_origin(&[])),
        "deleting domain block while CIDR block stays must prune deleted domain hints to empty"
    );
    fw.restore_promoted_filter_states(&rep_cidr_only.promoted_backups);
    assert_eq!(
        fw.filter_origin(perm_app, Some(blk_ip)),
        Some(&domain_policy_origin(&["blk2.example"]))
    );

    // 9. Baseline (`prev_rules`) attribution on failed DomainPolicy removal: deleting `R-ALLOW-1`
    //    while `remove_wfp_rule` fails records `R-ALLOW-1` in `source_rule_ids` so it matches
    //    the deleted allow rule and does NOT match an unrelated rule on the same executable.
    fw.restore_removed_domain_filters(std::slice::from_ref(perm_snap), &defense);
    let prev_allow_good1 = make_network_rule(
        "R-ALLOW-1",
        RuleScope::NetworkAllow,
        perm_app,
        Some(&sha_d),
        Some("good1.example"),
        1,
    );
    let unrelated_rule = make_network_rule(
        "R-UNRELATED",
        RuleScope::NetworkAllow,
        perm_app,
        Some(&sha_d),
        Some("unrelated.example"),
        5,
    );
    defense.set_fail_removes(true);
    let rep_del_fail = fw.reconcile_persisted_rules_with_baseline(
        &[cidr_block],
        Some(std::slice::from_ref(&prev_allow_good1)),
        &[],
        &inspector,
        &defense,
    );
    defense.set_fail_removes(false);
    assert!(
        rep_del_fail
            .failure_summary_for_rules(&[&prev_allow_good1])
            .is_some(),
        "failed DomainPolicy Permit removal must stay attributed to deleted R-ALLOW-1"
    );
    assert!(
        rep_del_fail
            .failure_summary_for_rules(&[&unrelated_rule])
            .is_none(),
        "failed DomainPolicy Permit removal must not block unrelated rules on same exe"
    );

    // 10. `ensure_domain_policy_block_hints` supports empty untagged slices (CIDR-only blocks),
    //     multi-hint normalization/dedup merging on reuse, and conflicting Permit replacement.
    let hints_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 90));
    let h_empty = fw
        .ensure_domain_policy_block_hints(perm_app, hints_ip, &[] as &[&str], &defense)
        .expect("install untagged CIDR DomainPolicy block");
    assert_eq!(
        fw.filter_origin(perm_app, Some(hints_ip)),
        Some(&domain_policy_origin(&[]))
    );
    let h_merged = fw
        .ensure_domain_policy_block_hints(
            perm_app,
            hints_ip,
            &["Blk1.Example.", "blk2.example", "blk1.example", ""],
            &defense,
        )
        .expect("merge multi-domain hints onto existing block");
    assert_eq!(h_empty, h_merged);
    assert_eq!(
        fw.filter_origin(perm_app, Some(hints_ip)),
        Some(&domain_policy_origin(&["blk1.example", "blk2.example"]))
    );
    let replace_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 91));
    fw.ensure_ip_permit_for_domain_rule(perm_app, replace_ip, "ok.example", &defense)
        .expect("install permit before block override");
    fw.ensure_domain_policy_block_hints(perm_app, replace_ip, &[] as &[&str], &defense)
        .expect("replace permit with untagged CIDR block");
    assert!(fw.has_active_filter(perm_app, Some(replace_ip), false));
    assert!(!fw.has_active_filter(perm_app, Some(replace_ip), true));
    assert_eq!(
        fw.filter_origin(perm_app, Some(replace_ip)),
        Some(&domain_policy_origin(&[]))
    );

    // 11. `reconcile_persisted_rules_with_dns_context` synchronizes live DNS-history domains
    //     into existing `DomainPolicy` Blocks so deleting a co-blocking CIDR or first domain
    //     rule keeps the block alive for a post-DNS domain block rule, and rollback restores
    //     pre-sync `domain_hints`.
    let mut fw_sync = WfpRuleManager::new();
    let sync_exe = r"C:\Tools\sync_dns_ctx.exe";
    let sync_exe_k = WfpRuleManager::exe_key(sync_exe);
    let sync_ip_cidr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 120));
    let sync_ip_dom = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 121));
    fw_sync
        .ensure_domain_policy_block_hints(sync_exe, sync_ip_cidr, &[] as &[&str], &defense)
        .expect("untagged CIDR block");
    fw_sync
        .ensure_domain_policy_block(sync_exe, sync_ip_dom, "blk-old.example", &defense)
        .expect("old domain block");
    let blk_new_rule = make_network_rule(
        "R-BLK-NEW",
        RuleScope::NetworkBlock,
        sync_exe,
        Some(&sha_d),
        Some("blk-new.example"),
        10,
    );
    let mut dns_ctx_sync = WfpReconcileDnsContext::default();
    dns_ctx_sync
        .active_block_domains
        .insert((sync_exe_k.clone(), sync_ip_cidr), str_vec(&["blk-new.example"]));
    dns_ctx_sync
        .active_block_domains
        .insert((sync_exe_k.clone(), sync_ip_dom), str_vec(&["blk-new.example"]));
    let rep_sync = fw_sync.reconcile_persisted_rules_with_dns_context(
        std::slice::from_ref(&blk_new_rule),
        None,
        &[],
        &dns_ctx_sync,
        &inspector,
        &defense,
    );
    assert_eq!(
        fw_sync.filter_origin(sync_exe, Some(sync_ip_cidr)),
        Some(&domain_policy_origin(&["blk-new.example"])),
        "existing untagged CIDR Block must survive via active DNS-history domain block"
    );
    assert_eq!(
        fw_sync.filter_origin(sync_exe, Some(sync_ip_dom)),
        Some(&domain_policy_origin(&["blk-new.example"])),
        "existing domain Block must transition to surviving active DNS-history domain block"
    );
    fw_sync.restore_promoted_filter_states(&rep_sync.promoted_backups);
    assert_eq!(
        fw_sync.filter_origin(sync_exe, Some(sync_ip_cidr)),
        Some(&domain_policy_origin(&[]))
    );
    assert_eq!(
        fw_sync.filter_origin(sync_exe, Some(sync_ip_dom)),
        Some(&domain_policy_origin(&["blk-old.example"]))
    );

    // 12. Migrated/superseded Permit hint pruning (`prune_migrated_domain_permit_hints_for_query`
    //     and `WfpReconcileDnsContext::superseded_permit_hints`):
    //     - Multi-domain Permit prunes migrated domain while keeping remaining domain intact.
    //     - Single-domain non-static Permit is NOT corrupted to empty `[]`.
    //     - CIDR Permit with superseded hint prunes to `[]` and survives when that domain is blocked.
    let mut fw_perm = WfpRuleManager::new();
    let perm_mig_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 140));
    let solo_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 141));
    let cidr_mig_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 142));
    let migrated_dest = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 199));
    fw_perm
        .ensure_ip_permit_for_domain_hints(
            sync_exe,
            perm_mig_ip,
            &["keep.example", "moved.example"],
            &defense,
        )
        .expect("multi-domain permit");
    fw_perm
        .ensure_ip_permit_for_domain_rule(sync_exe, solo_ip, "solo.example", &defense)
        .expect("single-domain permit");
    fw_perm
        .ensure_ip_permit_for_domain_rule(sync_exe, cidr_mig_ip, "cdn-moved.example", &defense)
        .expect("cidr-backed permit");

    let sync_identity = inspector.inspect(sync_exe);
    let allow_keep_mig = make_network_rule(
        "R-ALLOW-KEEP-MIG",
        RuleScope::NetworkAllow,
        sync_exe,
        Some(&sha_d),
        Some("keep.example"),
        10,
    );
    let allow_solo_mig = make_network_rule(
        "R-ALLOW-SOLO-MIG",
        RuleScope::NetworkAllow,
        sync_exe,
        Some(&sha_d),
        Some("solo.example"),
        10,
    );
    let mig_rules = [allow_keep_mig, allow_solo_mig];

    let pruned_multi = fw_perm.prune_migrated_domain_permit_hints_for_query(
        sync_exe,
        "moved.example",
        &[migrated_dest],
        &sync_identity,
        &mig_rules,
        &HashSet::new(),
    );
    assert_eq!(pruned_multi, 1);
    assert_eq!(
        fw_perm.filter_origin(sync_exe, Some(perm_mig_ip)),
        Some(&domain_policy_origin(&["keep.example"]))
    );
    let pruned_solo = fw_perm.prune_migrated_domain_permit_hints_for_query(
        sync_exe,
        "solo.example",
        &[migrated_dest],
        &sync_identity,
        &mig_rules,
        &HashSet::new(),
    );
    assert_eq!(
        pruned_solo, 0,
        "single-domain non-static Permit must not be corrupted into untagged []"
    );
    assert_eq!(
        fw_perm.filter_origin(sync_exe, Some(solo_ip)),
        Some(&domain_policy_origin(&["solo.example"]))
    );
    let allow_cidr_mig = make_network_rule(
        "R-ALLOW-CIDR-MIG",
        RuleScope::NetworkAllow,
        sync_exe,
        Some(&sha_d),
        Some("198.51.100.142/32"),
        11,
    );
    let blk_cdn_moved = make_network_rule(
        "R-BLK-CDN-MOVED",
        RuleScope::NetworkBlock,
        sync_exe,
        Some(&sha_d),
        Some("cdn-moved.example"),
        12,
    );
    let mut dns_ctx_perm = WfpReconcileDnsContext::default();
    dns_ctx_perm.superseded_permit_hints.insert((
        sync_exe_k.clone(),
        cidr_mig_ip,
        "cdn-moved.example".to_string(),
    ));
    let rep_cidr_survive = fw_perm.reconcile_persisted_rules_with_dns_context(
        &[allow_cidr_mig, blk_cdn_moved],
        None,
        &[],
        &dns_ctx_perm,
        &inspector,
        &defense,
    );
    assert!(
        fw_perm.has_active_filter(sync_exe, Some(cidr_mig_ip), true),
        "CIDR Permit must survive when superseded domain hint is blocked at its new IP"
    );
    assert_eq!(
        fw_perm.filter_origin(sync_exe, Some(cidr_mig_ip)),
        Some(&domain_policy_origin(&[]))
    );
    fw_perm.restore_promoted_filter_states(&rep_cidr_survive.promoted_backups);
    assert_eq!(
        fw_perm.filter_origin(sync_exe, Some(cidr_mig_ip)),
        Some(&domain_policy_origin(&["cdn-moved.example"]))
    );

    // 13. Override-removal `prev_rules` attribution: when an app-wide or literal-IP Block
    //     already overrides a stuck DomainPolicy Permit (or PersistedPolicy Permit) and
    //     `remove_wfp_rule` still fails, deleting the Permit's rule MUST stay attributed to
    //     the deleted allow rule while not blocking unrelated rules on the same executable.
    let mut fw_ov = WfpRuleManager::new();
    let ov_exe = r"C:\Tools\override_attr.exe";
    let ov_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 150));
    let ov_lit_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 151));
    fw_ov
        .ensure_ip_permit_for_domain_rule(ov_exe, ov_ip, "good-ov.example", &defense)
        .expect("install stuck domain permit");
    let r_ov_allow_dom = make_network_rule(
        "R-OV-ALLOW-DOM",
        RuleScope::NetworkAllow,
        ov_exe,
        Some(&sha_d),
        Some("good-ov.example"),
        20,
    );
    let r_ov_allow_lit = make_network_rule(
        "R-OV-ALLOW-LIT",
        RuleScope::NetworkAllow,
        ov_exe,
        Some(&sha_d),
        Some(&ov_lit_ip.to_string()),
        21,
    );
    // Materialize PersistedPolicy Permit for `ov_lit_ip`.
    fw_ov.reconcile_persisted_rules(
        &[r_ov_allow_dom.clone(), r_ov_allow_lit.clone()],
        &[],
        &inspector,
        &defense,
    );
    assert!(fw_ov.has_active_filter(ov_exe, Some(ov_lit_ip), true));
    let r_ov_blk_app = make_network_rule("R-OV-BLK-APP", RuleScope::NetworkBlock, ov_exe, Some(&sha_d), None, 22);
    let r_ov_blk_ip = make_network_rule(
        "R-OV-BLK-IP",
        RuleScope::NetworkBlock,
        ov_exe,
        Some(&sha_d),
        Some(&ov_ip.to_string()),
        23,
    );
    let r_ov_blk_lit = make_network_rule(
        "R-OV-BLK-LIT",
        RuleScope::NetworkBlock,
        ov_exe,
        Some(&sha_d),
        Some(&ov_lit_ip.to_string()),
        24,
    );
    let r_ov_unrelated = make_network_rule(
        "R-OV-UNRELATED",
        RuleScope::NetworkAllow,
        ov_exe,
        Some(&sha_d),
        Some("unrelated-ov.example"),
        25,
    );

    defense.set_fail_removes(true);
    // 13a: App-wide block overrides stuck DomainPolicy Permit while deleting R-OV-ALLOW-DOM.
    let rep_app_ov = fw_ov.reconcile_persisted_rules_with_baseline(
        std::slice::from_ref(&r_ov_blk_app),
        Some(&[r_ov_blk_app.clone(), r_ov_allow_dom.clone()]),
        &[],
        &inspector,
        &defense,
    );
    assert!(
        rep_app_ov
            .failure_summary_for_rules(&[&r_ov_allow_dom])
            .is_some(),
        "deleting R-OV-ALLOW-DOM under app-wide block must surface stuck Permit removal failure"
    );
    assert!(
        rep_app_ov
            .failure_summary_for_rules(&[&r_ov_unrelated])
            .is_none(),
        "unrelated domain rule must remain unblocked"
    );
    // 13b: Literal-IP block overrides stuck DomainPolicy Permit AND PersistedPolicy Permit
    //      while deleting R-OV-ALLOW-DOM and R-OV-ALLOW-LIT.
    let rep_ip_ov = fw_ov.reconcile_persisted_rules_with_baseline(
        &[r_ov_blk_ip.clone(), r_ov_blk_lit.clone()],
        Some(&[
            r_ov_blk_ip,
            r_ov_blk_lit,
            r_ov_allow_dom.clone(),
            r_ov_allow_lit.clone(),
        ]),
        &[],
        &inspector,
        &defense,
    );
    defense.set_fail_removes(false);
    assert!(
        rep_ip_ov
            .failure_summary_for_rules(&[&r_ov_allow_dom])
            .is_some(),
        "deleting R-OV-ALLOW-DOM under literal-IP block must surface stuck DomainPolicy Permit failure"
    );
    assert!(
        rep_ip_ov
            .failure_summary_for_rules(&[&r_ov_allow_lit])
            .is_some(),
        "deleting R-OV-ALLOW-LIT under literal-IP block must surface stuck PersistedPolicy Permit failure"
    );
    assert!(
        rep_ip_ov
            .failure_summary_for_rules(&[&r_ov_unrelated])
            .is_none(),
        "unrelated rule must remain unblocked"
    );
}

/// `FIREWALL-P3-48A` (`PRRT_kwDOVyjVyM65e5kL` + `AUD-P3-02`; unit-boundary counterpart to
/// integration test `DAEMON-P3-48`):
/// - Shared IP (`api.example` allowed + `other.example` unallowed) migrating `api.example`
///   retains the authorizing hint across DNS-time pruning and unrelated reconciliation;
/// - Subsequent migration of unallowed `other.example` selectively prunes `other.example`
///   while keeping `api.example` (with rollback fidelity);
/// - Multi-allow shared IP (`keep.example` + `api.example` + `other.example`) prunes the
///   migrating `api.example` so blocking `api.example` preserves `keep.example`'s Permit;
/// - Post-migration blocks (`R-BLK-OTHER` and `R-BLK-API`) and allow-rule deletion
///   (`R-ALLOW-API`) revoke the Permit with exact sole rule attribution and rollback fidelity;
/// - `ensure_ip_permit_for_domain_hints_prioritized` preserves insertion order within 32 hints
///   and protects authorizing hints from FIFO eviction on `MAX_DOMAIN_HINTS_PER_FILTER` overflow.
#[test]
fn firewall_p3_48a_shared_ip_authorizing_hint_retention_and_prioritized_cap() {
    let defense = StubDefense::new();
    let sha = "e".repeat(64);
    let inspector = StubInspector(sha.clone());
    let exe = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    let exe_k = WfpRuleManager::exe_key(exe);
    let identity = inspector.inspect(exe);
    let ip1 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 160));
    let ip1_v6_mapped = IpAddr::V6(Ipv4Addr::new(198, 51, 100, 160).to_ipv6_mapped());
    let ip2 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 161));
    let ip3 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 162));

    let mk_rule = |id: &str, scope: RuleScope, target: &str| {
        make_network_rule(id, scope, exe, Some(&sha), Some(target), 100)
    };

    let r_allow_api = mk_rule("R-ALLOW-API", RuleScope::NetworkAllow, "api.example");
    let r_allow_keep = mk_rule("R-ALLOW-KEEP", RuleScope::NetworkAllow, "keep.example");
    let r_blk_other = mk_rule("R-BLK-OTHER", RuleScope::NetworkBlock, "other.example");
    let r_blk_api = mk_rule("R-BLK-API", RuleScope::NetworkBlock, "api.example");
    let r_unrelated = make_network_rule(
        "R-UNRELATED",
        RuleScope::NetworkAllow,
        r"C:\Tools\other_unrelated.exe",
        Some(&sha),
        Some("unrelated.example"),
        101,
    );

    // 1. Shared IP (`api.example` allowed + `other.example` unallowed): `api.example` moves to
    //    `ip2` -> authorizing hint `api.example` MUST be retained across DNS-time pruning and
    //    unrelated rule reconciliation.
    let mut fw = WfpRuleManager::new();
    fw.ensure_ip_permit_for_domain_hints_prioritized(
        exe,
        ip1,
        &["api.example"],
        &["other.example"],
        &defense,
    )
    .expect("install shared-ip permit");
    assert_eq!(
        fw.domain_policy_permit_hints(exe, ip1),
        Some(str_vec(&["api.example", "other.example"]))
    );
    assert_eq!(
        fw.domain_policy_permit_hints(exe, ip1_v6_mapped),
        Some(str_vec(&["api.example", "other.example"])),
        "domain_policy_permit_hints must canonicalize IPv4-mapped IPv6 addresses"
    );
    assert_eq!(fw.domain_policy_permit_hints(exe, ip2), None);

    let mut sup_api_only: HashSet<(IpAddr, String)> = HashSet::new();
    sup_api_only.insert((ip1, "api.example".to_string()));
    let pruned_on_api_move = fw.prune_migrated_domain_permit_hints_for_query(
        exe,
        "api.example",
        &[ip2],
        &identity,
        std::slice::from_ref(&r_allow_api),
        &sup_api_only,
    );
    assert_eq!(
        pruned_on_api_move, 0,
        "migrating the sole authorizing domain while unallowed co-hosted hint remains must keep authorizing hint"
    );
    assert_eq!(
        fw.domain_policy_permit_hints(exe, ip1),
        Some(str_vec(&["api.example", "other.example"]))
    );

    let mut dns_ctx_api_sup = WfpReconcileDnsContext::default();
    dns_ctx_api_sup
        .superseded_permit_hints
        .insert((exe_k.clone(), ip1, "api.example".to_string()));
    let rep_unrel = fw.reconcile_persisted_rules_with_dns_context(
        &[r_allow_api.clone(), r_unrelated.clone()],
        Some(std::slice::from_ref(&r_allow_api)),
        &[],
        &dns_ctx_api_sup,
        &inspector,
        &defense,
    );
    assert_eq!(rep_unrel.removed, 0);
    assert!(
        fw.has_active_filter(exe, Some(ip1), true),
        "unrelated rule reconciliation must preserve cached-IP Permit after authorizing domain migration"
    );
    assert_eq!(
        fw.domain_policy_permit_hints(exe, ip1),
        Some(str_vec(&["api.example", "other.example"]))
    );

    // 2. Subsequent migration of unallowed `other.example` to `ip3`:
    //    2a. Via `reconcile_persisted_rules_with_dns_context` (selective pruning + rollback).
    let mut dns_ctx_both_sup = WfpReconcileDnsContext::default();
    dns_ctx_both_sup
        .superseded_permit_hints
        .insert((exe_k.clone(), ip1, "api.example".to_string()));
    dns_ctx_both_sup
        .superseded_permit_hints
        .insert((exe_k.clone(), ip1, "other.example".to_string()));
    let rep_other_sup = fw.reconcile_persisted_rules_with_dns_context(
        &[r_allow_api.clone(), r_blk_other.clone()],
        Some(std::slice::from_ref(&r_allow_api)),
        &[],
        &dns_ctx_both_sup,
        &inspector,
        &defense,
    );
    assert!(
        fw.has_active_filter(exe, Some(ip1), true),
        "blocking unallowed co-hosted domain after it also migrated must NOT revoke Permit"
    );
    assert_eq!(
        fw.domain_policy_permit_hints(exe, ip1),
        Some(str_vec(&["api.example"])),
        "reconcile must selectively prune retired unallowed co-hosted hint while retaining authorizing hint"
    );
    fw.restore_promoted_filter_states(&rep_other_sup.promoted_backups);
    assert_eq!(
        fw.domain_policy_permit_hints(exe, ip1),
        Some(str_vec(&["api.example", "other.example"])),
        "rollback must faithfully restore pre-reconcile Permit hints"
    );

    //    2b. Via `prune_migrated_domain_permit_hints_for_query` on `other.example -> ip3`.
    let mut sup_both: HashSet<(IpAddr, String)> = HashSet::new();
    sup_both.insert((ip1, "api.example".to_string()));
    sup_both.insert((ip1, "other.example".to_string()));
    let pruned_other = fw.prune_migrated_domain_permit_hints_for_query(
        exe,
        "other.example",
        &[ip3],
        &identity,
        std::slice::from_ref(&r_allow_api),
        &sup_both,
    );
    assert_eq!(pruned_other, 1);
    assert_eq!(
        fw.domain_policy_permit_hints(exe, ip1),
        Some(str_vec(&["api.example"])),
        "DNS-time pruning must selectively drop migrated unallowed other.example while keeping api.example"
    );

    // Re-restore `other.example` onto `ip1` Permit to test post-migration block & delete attribution.
    fw.ensure_ip_permit_for_domain_hints_prioritized(
        exe,
        ip1,
        &["api.example"],
        &["other.example"],
        &defense,
    )
    .expect("re-merge other.example");
    assert_eq!(
        fw.domain_policy_permit_hints(exe, ip1),
        Some(str_vec(&["api.example", "other.example"]))
    );

    // 3-5 (failure attribution): Post-migration `R-BLK-OTHER`, `R-BLK-API` (even though
    // `api.example` is superseded), and deletion of `R-ALLOW-API` sole attribution.
    struct AttributionCase<'a> {
        label: &'a str,
        desired_rules: Vec<AllowlistRuleRecord>,
        expected_rule_id: &'a str,
        expected_hints: Option<&'a [&'a str]>,
        matched_rule: &'a AllowlistRuleRecord,
        unmatched_rules: Vec<&'a AllowlistRuleRecord>,
        attribution_msg: &'a str,
    }
    defense.set_fail_removes(true);
    let attribution_cases = [
        AttributionCase {
            label: "3: R-BLK-OTHER",
            desired_rules: vec![r_allow_api.clone(), r_blk_other.clone()],
            expected_rule_id: "R-BLK-OTHER",
            expected_hints: Some(&["other.example"]),
            matched_rule: &r_blk_other,
            unmatched_rules: vec![&r_allow_api, &r_unrelated],
            attribution_msg: "blocking still-cohosted other.example must attribute solely to R-BLK-OTHER",
        },
        AttributionCase {
            label: "4: R-BLK-API",
            desired_rules: vec![r_allow_api.clone(), r_blk_api.clone()],
            expected_rule_id: "R-BLK-API",
            expected_hints: Some(&["api.example"]),
            matched_rule: &r_blk_api,
            unmatched_rules: vec![&r_allow_api, &r_unrelated],
            attribution_msg: "blocking migrated authorizing api.example must attribute solely to R-BLK-API",
        },
        AttributionCase {
            label: "5: delete R-ALLOW-API",
            desired_rules: vec![],
            expected_rule_id: "R-ALLOW-API",
            expected_hints: None,
            matched_rule: &r_allow_api,
            unmatched_rules: vec![&r_unrelated],
            attribution_msg: "deleting R-ALLOW-API after migration must attribute solely to R-ALLOW-API",
        },
    ];
    for case in &attribution_cases {
        let rep = fw.reconcile_persisted_rules_with_dns_context(
            &case.desired_rules,
            Some(std::slice::from_ref(&r_allow_api)),
            &[],
            &dns_ctx_api_sup,
            &inspector,
            &defense,
        );
        assert_eq!(rep.failed_ops.len(), 1, "{}", case.label);
        assert_eq!(
            rep.failed_ops[0].source_rule_ids,
            str_vec(&[case.expected_rule_id]),
            "{}",
            case.attribution_msg
        );
        if let Some(hints) = case.expected_hints {
            assert_eq!(rep.failed_ops[0].domain_hints, str_vec(hints), "{}", case.label);
        }
        assert!(
            rep.failure_summary_for_rules(&[case.matched_rule]).is_some(),
            "{}: matched rule must surface failure",
            case.label
        );
        for unmatched in &case.unmatched_rules {
            assert!(
                rep.failure_summary_for_rules(&[unmatched]).is_none(),
                "{}: unmatched rule {} must not surface failure",
                case.label,
                unmatched.rule_id
            );
        }
    }

    // 5 (removal rollback fidelity): deletion succeeds when `remove_wfp_rule` succeeds.
    defense.set_fail_removes(false);
    let rep_del_ok = fw.reconcile_persisted_rules_with_dns_context(
        &[],
        Some(std::slice::from_ref(&r_allow_api)),
        &[],
        &dns_ctx_api_sup,
        &inspector,
        &defense,
    );
    assert!(!fw.has_active_filter(exe, Some(ip1), true));
    assert_eq!(rep_del_ok.removed_domain_filters.len(), 1);
    assert_eq!(
        rep_del_ok.removed_domain_filters[0].domain_hints,
        str_vec(&["api.example", "other.example"])
    );
    fw.restore_removed_domain_filters(&rep_del_ok.removed_domain_filters, &defense);
    assert!(fw.has_active_filter(exe, Some(ip1), true));
    assert_eq!(
        fw.domain_policy_permit_hints(exe, ip1),
        Some(str_vec(&["api.example", "other.example"])),
        "restore_removed_domain_filters must restore exact pre-removal Permit hints"
    );

    // 6. Multiple allowed domains (`keep.example` + `api.example` + `other.example`) sharing
    //    `ip1`: when `api.example` moves to `ip2`, `keep.example` preserves `AllowedByRule`,
    //    so `api.example` IS pruned and later `R-BLK-API` preserves `ip1` Permit.
    let mut fw_multi = WfpRuleManager::new();
    fw_multi
        .ensure_ip_permit_for_domain_hints_prioritized(
            exe,
            ip1,
            &["keep.example", "api.example"],
            &["other.example"],
            &defense,
        )
        .expect("install multi-allow permit");
    let pruned_multi_allow = fw_multi.prune_migrated_domain_permit_hints_for_query(
        exe,
        "api.example",
        &[ip2],
        &identity,
        &[r_allow_keep.clone(), r_allow_api.clone()],
        &sup_api_only,
    );
    assert_eq!(pruned_multi_allow, 1);
    assert_eq!(
        fw_multi.domain_policy_permit_hints(exe, ip1),
        Some(str_vec(&["keep.example", "other.example"]))
    );
    let rep_multi_blk_api = fw_multi.reconcile_persisted_rules_with_dns_context(
        &[r_allow_keep, r_allow_api.clone(), r_blk_api],
        None,
        &[],
        &dns_ctx_api_sup,
        &inspector,
        &defense,
    );
    assert_eq!(rep_multi_blk_api.removed, 0);
    assert!(
        fw_multi.has_active_filter(exe, Some(ip1), true),
        "blocking migrated api.example must preserve ip1 Permit when keep.example remains allowed"
    );

    // 7. `MAX_DOMAIN_HINTS_PER_FILTER` (32) overflow protection (`AUD-P3-02`):
    let mut fw_cap = WfpRuleManager::new();
    let cap_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 170));
    let cap_full_auth_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 171));
    let cap_blk_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 172));

    // 7a. Within 32 hints: preserves insertion order.
    fw_cap
        .ensure_ip_permit_for_domain_hints_prioritized(
            exe,
            cap_ip,
            &["api.example"],
            &["c00.example", "c01.example"],
            &defense,
        )
        .expect("install initial prioritized permit");
    assert_eq!(
        fw_cap.domain_policy_permit_hints(exe, cap_ip),
        Some(str_vec(&["api.example", "c00.example", "c01.example"]))
    );

    // 7b. Overflow with 40 co-hosted hints: len bounded at 32 and `api.example` is NEVER evicted.
    let many_cohosts: Vec<String> = (0..40).map(|i| format!("c{i:02}.example")).collect();
    fw_cap
        .ensure_ip_permit_for_domain_hints_prioritized(
            exe,
            cap_ip,
            &["api.example"],
            &many_cohosts,
            &defense,
        )
        .expect("merge 40 cohosted hints");
    let hints_after = fw_cap
        .domain_policy_permit_hints(exe, cap_ip)
        .expect("permit hints after overflow");
    assert_eq!(hints_after.len(), MAX_DOMAIN_HINTS_PER_FILTER);
    assert!(
        hints_after.iter().any(|h| h == "api.example"),
        "authorizing hint api.example must never be FIFO-evicted by co-hosted hints"
    );
    assert_eq!(hints_after[0], "api.example");
    assert_eq!(hints_after[1], "c09.example");
    assert_eq!(hints_after[MAX_DOMAIN_HINTS_PER_FILTER - 1], "c39.example");

    // Re-merging additional co-hosted hints onto an already-full Permit still retains `api.example`.
    fw_cap
        .ensure_ip_permit_for_domain_hints_prioritized(
            exe,
            cap_ip,
            &["api.example"],
            &["c40.example", "c41.example"],
            &defense,
        )
        .expect("merge extra cohosted hints");
    let hints_after_extra = fw_cap
        .domain_policy_permit_hints(exe, cap_ip)
        .expect("permit hints after extra cohost merge");
    assert_eq!(hints_after_extra.len(), MAX_DOMAIN_HINTS_PER_FILTER);
    assert!(hints_after_extra.iter().any(|h| h == "api.example"));
    assert!(hints_after_extra.iter().any(|h| h == "c41.example"));
    assert!(!hints_after_extra.iter().any(|h| h == "c09.example"));

    // 7c. All 32 slots occupied by authorizing hints: co-hosted hints never evict any of them.
    let all_auth: Vec<String> = (0..MAX_DOMAIN_HINTS_PER_FILTER)
        .map(|i| format!("auth{i:02}.example"))
        .collect();
    fw_cap
        .ensure_ip_permit_for_domain_hints_prioritized(
            exe,
            cap_full_auth_ip,
            &all_auth,
            &["cohost-extra.example"],
            &defense,
        )
        .expect("install 32 authorizing hints");
    let full_auth_hints = fw_cap
        .domain_policy_permit_hints(exe, cap_full_auth_ip)
        .expect("32 auth permit hints");
    assert_eq!(full_auth_hints, all_auth);

    // 7d. Existing IP Block conflict still returns Ok(None) (deny-overrides-allow).
    fw_cap
        .ensure_domain_policy_block(exe, cap_blk_ip, "bad.example", &defense)
        .expect("install block");
    let suppressed = fw_cap
        .ensure_ip_permit_for_domain_hints_prioritized(
            exe,
            cap_blk_ip,
            &["api.example"],
            &["other.example"],
            &defense,
        )
        .expect("conflict returns Ok(None)");
    assert_eq!(suppressed, None);
    assert_eq!(fw_cap.domain_policy_permit_hints(exe, cap_blk_ip), None);

    // 8. Static CIDR `NetworkAllow` overridden by static CIDR `NetworkBlock`: retired
    //    unallowed co-hosted hint `other.example` must NOT be treated as domain-authorized
    //    by the CIDR allow rule, so `R-BLK-OTHER` is never falsely attributed on `ip1`.
    let mut fw_cidr_override = WfpRuleManager::new();
    fw_cidr_override
        .ensure_ip_permit_for_domain_hints_prioritized(
            exe,
            ip1,
            &[] as &[&str],
            &["api.example", "other.example"],
            &defense,
        )
        .expect("install cidr shared-ip permit");
    let r_allow_cidr = mk_rule("R-ALLOW-CIDR", RuleScope::NetworkAllow, "198.51.100.0/24");
    let r_blk_cidr = mk_rule("R-BLK-CIDR", RuleScope::NetworkBlock, "198.51.100.0/24");
    let mut dns_ctx_other_sup = WfpReconcileDnsContext::default();
    dns_ctx_other_sup
        .superseded_permit_hints
        .insert((exe_k.clone(), ip1, "other.example".to_string()));
    defense.set_fail_removes(true);
    let rep_cidr_blk_fail = fw_cidr_override.reconcile_persisted_rules_with_dns_context(
        &[r_allow_cidr.clone(), r_blk_cidr.clone(), r_blk_other.clone()],
        Some(&[r_allow_cidr, r_blk_other.clone()]),
        &[],
        &dns_ctx_other_sup,
        &inspector,
        &defense,
    );
    defense.set_fail_removes(false);
    assert_eq!(rep_cidr_blk_fail.failed_ops.len(), 1);
    assert_eq!(
        rep_cidr_blk_fail.failed_ops[0].source_rule_ids,
        str_vec(&["R-BLK-CIDR"]),
        "overridden static CIDR allow must not retain retired unallowed other.example or attribute R-BLK-OTHER"
    );
    assert_eq!(
        rep_cidr_blk_fail.failed_ops[0].domain_hints,
        str_vec(&["api.example"])
    );
    assert!(rep_cidr_blk_fail
        .failure_summary_for_rules(&[&r_blk_cidr])
        .is_some());
    assert!(rep_cidr_blk_fail
        .failure_summary_for_rules(&[&r_blk_other])
        .is_none());
}

/// Regression test `WFP-DEFERRED-01` (`PRRT_kwDOVyjVyM66kfDX`):
/// verifies `deferred_preemptive_removals` lifecycle across alert-bound ProcessStop deferral,
/// pending->deferred handoff on alert rebind, live process reclaim, and startup-pinning prune.
#[test]
fn firewall_deferred_preemptive_removal_tracks_bound_alert_and_reclaim_lifecycle() {
    let mut fw = WfpRuleManager::new();
    let defense = StubDefense::new();

    // 1. ProcessStop attempts removal while an unresolved alert still references the Preemptive
    //    block -> deferred marker is set, pending queue stays empty (sweep stays O(1)).
    let exe_bound = r"C:\Users\Alice\Downloads\bound_then_stop.exe";
    let h_bound = defense.add_wfp_app_rule(Path::new(exe_bound), None, false).unwrap();
    assert!(fw.register_preemptive_block(exe_bound, h_bound, &defense));
    assert!(fw.bind_alert_to_app_block("ALT-NET-1", exe_bound));
    assert!(!fw.remove_preemptive_block_if_unused(exe_bound, &defense));
    assert!(fw.has_deferred_preemptive_removal(exe_bound));
    assert!(!fw.has_pending_preemptive_removal(exe_bound));
    let mut probe_calls = 0usize;
    assert_eq!(
        fw.sweep_unused_preemptive_blocks(
            |_| {
                probe_calls += 1;
                false
            },
            &defense
        ),
        0
    );
    assert_eq!(
        probe_calls, 0,
        "deferred removal while alert is bound must not break sweep's O(1) fast path"
    );

    // Releasing the last bound alert without removing the Preemptive filter keeps deferred flag
    // until caller explicitly retries `remove_preemptive_block_if_unused`.
    let (snap, was_bound) = fw
        .release_transient_containment_for_alert("ALT-NET-1", Some(exe_bound), &defense)
        .expect("release alert binding");
    assert!(snap.is_none());
    assert!(was_bound);
    assert!(!fw.has_any_bound_alerts_for_exe(exe_bound));
    assert!(fw.has_deferred_preemptive_removal(exe_bound));
    assert!(fw.remove_preemptive_block_if_unused(exe_bound, &defense));
    assert!(!fw.has_any_app_filter(exe_bound));
    assert!(!fw.has_deferred_preemptive_removal(exe_bound));

    // 2. Binding an alert to a handle already in `pending_preemptive_removals` moves it from
    //    `pending` to `deferred` so periodic sweep skips it while bound, yet releasing the alert
    //    retains the fact that ProcessStop already requested removal.
    let exe_rebound = r"C:\Users\Alice\Downloads\pending_to_deferred.exe";
    defense.set_fail_removes(true);
    let h_rebound = defense
        .add_wfp_app_rule(Path::new(exe_rebound), None, false)
        .unwrap();
    assert!(!fw.discard_obsolete_preemptive_block(exe_rebound, h_rebound, &defense));
    defense.set_fail_removes(false);
    assert!(fw.has_pending_preemptive_removal(exe_rebound));
    assert!(fw.bind_alert_to_app_block("ALT-NET-2", exe_rebound));
    assert!(!fw.has_pending_preemptive_removal(exe_rebound));
    assert!(fw.has_deferred_preemptive_removal(exe_rebound));

    // 3. Reclaiming the block for a newly started live process clears `deferred_preemptive_removals`.
    assert!(fw.clear_pending_preemptive_removal(exe_rebound));
    assert!(!fw.has_deferred_preemptive_removal(exe_rebound));

    // 4. Startup-pinning prunes deferred removal.
    let exe_pin = r"C:\Users\Alice\Downloads\deferred_then_pinned.exe";
    let h_pin = defense.add_wfp_app_rule(Path::new(exe_pin), None, false).unwrap();
    assert!(fw.register_preemptive_block(exe_pin, h_pin, &defense));
    assert!(fw.bind_alert_to_app_block("ALT-NET-3", exe_pin));
    assert!(!fw.remove_preemptive_block_if_unused(exe_pin, &defense));
    assert!(fw.has_deferred_preemptive_removal(exe_pin));
    fw.set_startup_preemptive_executables(&[exe_pin.to_string()]);
    assert!(!fw.has_deferred_preemptive_removal(exe_pin));
}

/// Regression test `WFP-ROLLBACK-01` (`PRRT_kwDOVyjVyM66kfDu`):
/// verifies `restore_promoted_filter_states` faithfully restores both
/// `pending_preemptive_removals` (including consecutive backoff failure count) and
/// `deferred_preemptive_removals` when a policy reconciliation pass rolls back.
#[test]
fn firewall_restore_promoted_filter_states_preserves_pending_and_deferred_preemptive_removals() {
    let mut fw = WfpRuleManager::new();
    let defense = StubDefense::new();
    let inspector = StubInspector("a".repeat(64));

    let pending_exe = r"C:\Users\Alice\Downloads\rollback_pending.exe";
    let deferred_exe = r"C:\Users\Alice\Downloads\rollback_deferred.exe";

    // Queue `pending_exe` into `pending_preemptive_removals` and accumulate 2 sweep failures.
    defense.set_fail_removes(true);
    let h_pending = defense
        .add_wfp_app_rule(Path::new(pending_exe), None, false)
        .unwrap();
    assert!(!fw.discard_obsolete_preemptive_block(pending_exe, h_pending, &defense));
    assert_eq!(fw.sweep_unused_preemptive_blocks(|_| false, &defense), 0);
    assert_eq!(fw.sweep_unused_preemptive_blocks(|_| false, &defense), 0);
    assert!(fw.has_pending_preemptive_removal(pending_exe));
    defense.set_fail_removes(false);

    // Queue `deferred_exe` into `deferred_preemptive_removals` while an alert is bound.
    let h_deferred = defense
        .add_wfp_app_rule(Path::new(deferred_exe), None, false)
        .unwrap();
    assert!(fw.register_preemptive_block(deferred_exe, h_deferred, &defense));
    assert!(fw.bind_alert_to_app_block("ALT-ROLLBACK-1", deferred_exe));
    assert!(!fw.remove_preemptive_block_if_unused(deferred_exe, &defense));
    assert!(fw.has_deferred_preemptive_removal(deferred_exe));

    // Reconcile promotes both Preemptive blocks to `PersistedPolicy`, clearing pending/deferred.
    let rules = vec![
        AllowlistRuleRecord {
            rule_id: "R-BLK-PENDING".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: pending_exe.to_string(),
            sha256: None,
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: None,
            created_at_ms: 1,
            created_by: "test".to_string(),
        },
        AllowlistRuleRecord {
            rule_id: "R-BLK-DEFERRED".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: deferred_exe.to_string(),
            sha256: None,
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: None,
            created_at_ms: 2,
            created_by: "test".to_string(),
        },
    ];
    let report = fw.reconcile_persisted_rules(&rules, &[], &inspector, &defense);
    assert_eq!(report.promoted, 2);
    assert_eq!(
        fw.filter_origin(pending_exe, None),
        Some(&WfpFilterOrigin::PersistedPolicy)
    );
    assert_eq!(
        fw.filter_origin(deferred_exe, None),
        Some(&WfpFilterOrigin::PersistedPolicy)
    );
    assert!(!fw.has_pending_preemptive_removal(pending_exe));
    assert!(!fw.has_deferred_preemptive_removal(deferred_exe));
    assert!(!fw.is_alert_bound("ALT-ROLLBACK-1"));

    // Roll back promotions -> origins, bound alerts, pending queue (with failure count), and
    // deferred marker are all restored.
    fw.restore_promoted_filter_states(&report.promoted_backups);
    assert_eq!(
        fw.filter_origin(pending_exe, None),
        Some(&WfpFilterOrigin::Preemptive)
    );
    assert_eq!(
        fw.filter_origin(deferred_exe, None),
        Some(&WfpFilterOrigin::Preemptive)
    );
    assert!(fw.has_pending_preemptive_removal(pending_exe));
    assert!(fw.has_deferred_preemptive_removal(deferred_exe));
    assert!(fw.is_alert_bound("ALT-ROLLBACK-1"));

    // Periodic sweep immediately recovers `pending_exe` (while leaving `deferred_exe` bound).
    assert_eq!(fw.sweep_unused_preemptive_blocks(|_| false, &defense), 1);
    assert!(!fw.has_any_app_filter(pending_exe));
    assert!(fw.has_active_filter(deferred_exe, None, false));
}

/// Regression test `WFP-ROLLBACK-03` (`PRRT_kwDOVyjVyM66ksZF`):
/// verifies that removed-block snapshots (`snapshot_app_block_and_bindings`,
/// `lift_block_for_allow_once`, and `WfpReconcileReport::removed_app_blocks`) preserve
/// `prev_deferred_preemptive_removal` and `prev_pending_removal_failures`, and that
/// `restore_lifted_block` / `restore_removed_app_blocks` faithfully restore those states while
/// avoiding re-adding dead unbound `pending_preemptive_removals` filters deleted by reconcile.
#[test]
fn firewall_removed_block_snapshots_and_reconcile_rollback_preserve_deferred_and_pending_state() {
    let defense = StubDefense::new();
    let inspector = StubInspector("a".repeat(64));
    let mut fw = WfpRuleManager::new();

    // 1. `snapshot_app_block_and_bindings` + `restore_lifted_block` preserve deferred removal.
    let exe_deferred = r"C:\Users\Alice\Downloads\rollback_deferred_snap.exe";
    let h1 = defense
        .add_wfp_app_rule(Path::new(exe_deferred), None, false)
        .unwrap();
    assert!(fw.register_preemptive_block(exe_deferred, h1, &defense));
    assert!(fw.bind_alert_to_app_block("ALT-SNAP-1", exe_deferred));
    assert!(!fw.remove_preemptive_block_if_unused(exe_deferred, &defense));
    assert!(fw.has_deferred_preemptive_removal(exe_deferred));

    let (snap_opt, sibs) = fw.snapshot_app_block_and_bindings(exe_deferred);
    let snap = snap_opt.expect("snapshot must capture Preemptive block");
    assert!(snap.prev_deferred_preemptive_removal);
    assert_eq!(snap.prev_pending_removal_failures, None);
    assert_eq!(sibs, vec!["ALT-SNAP-1".to_string()]);

    // App-wide `NetworkAllow` reconciliation removes the Preemptive block and records it in
    // `report.removed_app_blocks` with its deferred flag and bound alert.
    let allow_rule = AllowlistRuleRecord {
        rule_id: "R-ALLOW-SNAP-1".to_string(),
        scope: RuleScope::NetworkAllow,
        exe_path_pattern: exe_deferred.to_string(),
        sha256: Some("a".repeat(64)),
        signer_subject: None,
        root_thumbprint: None,
        allowed_target: None,
        created_at_ms: 1,
        created_by: "test".to_string(),
    };
    let report = fw.reconcile_persisted_rules(&[allow_rule], &[], &inspector, &defense);
    assert_eq!(report.removed_app_blocks.len(), 1);
    assert!(report.removed_app_blocks[0].block.prev_deferred_preemptive_removal);
    assert_eq!(
        report.removed_app_blocks[0].bound_alert_ids,
        vec!["ALT-SNAP-1".to_string()]
    );
    assert!(fw.has_active_filter(exe_deferred, None, true));

    // Roll back the allow rule (removing Permit) and restore via `restore_removed_app_blocks`.
    let _ = fw.reconcile_persisted_rules(&[], &[], &inspector, &defense);
    assert!(!fw.has_any_app_filter(exe_deferred));
    fw.restore_removed_app_blocks(&report.removed_app_blocks, |_| false, &defense);
    assert_eq!(
        fw.filter_origin(exe_deferred, None),
        Some(&WfpFilterOrigin::Preemptive)
    );
    assert!(fw.is_alert_bound("ALT-SNAP-1"));
    assert!(
        fw.has_deferred_preemptive_removal(exe_deferred),
        "restore_removed_app_blocks must restore deferred_preemptive_removals on the new handle"
    );

    // Also verify `lift_block_for_allow_once` + `restore_lifted_block` preserves deferred state.
    let (lifted_opt, was_bound) = fw
        .lift_block_for_allow_once("ALT-SNAP-1", exe_deferred, false, &defense)
        .expect("lift_block_for_allow_once");
    assert!(was_bound);
    let lifted = lifted_opt.expect("lifted snapshot");
    assert!(lifted.prev_deferred_preemptive_removal);
    assert!(!fw.has_any_app_filter(exe_deferred));

    fw.restore_lifted_block(Some("ALT-SNAP-1"), lifted, &defense);
    assert_eq!(
        fw.filter_origin(exe_deferred, None),
        Some(&WfpFilterOrigin::Preemptive)
    );
    assert!(fw.is_alert_bound("ALT-SNAP-1"));
    assert!(
        fw.has_deferred_preemptive_removal(exe_deferred),
        "restore_lifted_block must restore deferred_preemptive_removals on the new handle"
    );

    // 2. Dead unbound `pending_preemptive_removals` handle deleted by reconcile must NOT be
    //    re-added by `restore_removed_app_blocks` (BFE deletion already succeeded).
    let exe_dead_pending = r"C:\Users\Alice\Downloads\rollback_dead_pending.exe";
    let h2 = defense
        .add_wfp_app_rule(Path::new(exe_dead_pending), None, false)
        .unwrap();
    assert!(fw.register_preemptive_block(exe_dead_pending, h2, &defense));
    defense.set_fail_removes(true);
    assert!(!fw.remove_preemptive_block_if_unused(exe_dead_pending, &defense));
    assert!(fw.has_pending_preemptive_removal(exe_dead_pending));
    defense.set_fail_removes(false);

    let allow_dead = AllowlistRuleRecord {
        rule_id: "R-ALLOW-DEAD-2".to_string(),
        scope: RuleScope::NetworkAllow,
        exe_path_pattern: exe_dead_pending.to_string(),
        sha256: Some("a".repeat(64)),
        signer_subject: None,
        root_thumbprint: None,
        allowed_target: None,
        created_at_ms: 2,
        created_by: "test".to_string(),
    };
    let report_dead = fw.reconcile_persisted_rules(&[allow_dead], &[], &inspector, &defense);
    assert!(
        report_dead.removed_app_blocks.is_empty(),
        "successfully deleted unbound pending-removal block must not be queued for rollback restoration"
    );
}

/// Regression test `WFP-ROLLBACK-05` (`PRRT_kwDOVyjVyM66k6kK`):
/// verifies that `restore_removed_app_blocks` checks executable liveness via `is_exe_active`
/// before restoring non-startup `Preemptive` blocks:
/// - unbound non-startup `Preemptive` for an exited app is NOT resurrected;
/// - unbound non-startup `Preemptive` for an active app IS restored;
/// - startup-pinned `Preemptive` is always restored even when no instance is running;
/// - alert-bound non-startup `Preemptive` for an exited app IS restored with
///   `deferred_preemptive_removals` set so resolving the final bound alert cleans it up.
#[test]
fn firewall_restore_removed_app_blocks_skips_exited_unbound_preemptive_and_marks_exited_bound_deferred() {
    let defense = StubDefense::new();
    let inspector = StubInspector("b".repeat(64));
    let mut fw = WfpRuleManager::new();

    let exe_exited_unbound = r"C:\Users\Alice\Downloads\rb5_exited_unbound.exe";
    let exe_active_unbound = r"C:\Users\Alice\Downloads\rb5_active_unbound.exe";
    let exe_startup_pinned = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    let exe_exited_bound = r"C:\Users\Alice\Downloads\rb5_exited_bound.exe";

    for exe in [
        exe_exited_unbound,
        exe_active_unbound,
        exe_startup_pinned,
        exe_exited_bound,
    ] {
        let h = defense.add_wfp_app_rule(Path::new(exe), None, false).unwrap();
        assert!(fw.register_preemptive_block(exe, h, &defense));
    }
    assert!(fw.bind_alert_to_app_block("ALT-RB5-BOUND", exe_exited_bound));

    let startup_candidates = vec![exe_startup_pinned.to_string()];
    fw.set_startup_preemptive_executables(&startup_candidates);
    assert!(fw.is_startup_preemptive(exe_startup_pinned));

    let make_allow = |id: &str, exe: &str| AllowlistRuleRecord {
        rule_id: id.to_string(),
        scope: RuleScope::NetworkAllow,
        exe_path_pattern: exe.to_string(),
        sha256: Some("b".repeat(64)),
        signer_subject: None,
        root_thumbprint: None,
        allowed_target: None,
        created_at_ms: 1,
        created_by: "test".to_string(),
    };
    let allows = vec![
        make_allow("R-RB5-1", exe_exited_unbound),
        make_allow("R-RB5-2", exe_active_unbound),
        make_allow("R-RB5-3", exe_startup_pinned),
        make_allow("R-RB5-4", exe_exited_bound),
    ];
    let report = fw.reconcile_persisted_rules(&allows, &startup_candidates, &inspector, &defense);
    assert_eq!(report.removed_app_blocks.len(), 4);

    // Roll back persisted rules (removing Permits, and startup_pinned will be re-installed or kept
    // absent if we reconcile with empty startup_candidates first so we test restore_removed_app_blocks
    // directly for startup_pinned too).
    let _ = fw.reconcile_persisted_rules(&[], &[], &inspector, &defense);
    // Keep startup_pinned registered in `startup_preemptive_exes` without an installed filter by
    // simulating rollback before startup reconcile: remove only its handle cleanly.
    assert!(fw.is_startup_preemptive(exe_startup_pinned));
    assert!(!fw.has_any_app_filter(exe_exited_unbound));
    assert!(!fw.has_any_app_filter(exe_active_unbound));
    assert!(!fw.has_any_app_filter(exe_exited_bound));

    let active_key = WfpRuleManager::exe_key(exe_active_unbound);
    fw.restore_removed_app_blocks(
        &report.removed_app_blocks,
        |exe_key| exe_key == active_key,
        &defense,
    );

    assert!(
        !fw.has_any_app_filter(exe_exited_unbound),
        "exited unbound non-startup Preemptive block must NOT be resurrected on rollback"
    );
    assert_eq!(
        fw.filter_origin(exe_active_unbound, None),
        Some(&WfpFilterOrigin::Preemptive),
        "still-active non-startup Preemptive block must be restored on rollback"
    );
    assert!(
        !fw.has_deferred_preemptive_removal(exe_active_unbound),
        "still-active non-startup Preemptive block must not be marked deferred"
    );
    assert_eq!(
        fw.filter_origin(exe_startup_pinned, None),
        Some(&WfpFilterOrigin::Preemptive),
        "startup-pinned Preemptive block must remain active on rollback"
    );
    assert_eq!(
        fw.filter_origin(exe_exited_bound, None),
        Some(&WfpFilterOrigin::Preemptive),
        "alert-bound Preemptive block for an exited app must be restored until alert resolves"
    );
    assert!(fw.is_alert_bound("ALT-RB5-BOUND"));
    assert!(
        fw.has_deferred_preemptive_removal(exe_exited_bound),
        "alert-bound Preemptive block whose process exited before rollback must be marked deferred"
    );
}
