use super::*;
use super::cmdline_correlator::ProcessCommandLineCorrelator;
use super::context::{EtwCallbackContext, HoneypotHandleTracker, lookup_registry_key};
use super::handlers::buffer_callback;
use super::registry::{RegistryEventFacts, RegistryKeyName, decide_registry_event};
use super::session::ActiveEtwSession;
use super::tdh::{self, parse_dns_query_results};
use std::collections::HashMap;
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock, mpsc};
use std::thread;
use ledr_proto::{CanaryCategory, ProcessIdentity, SensorBackend, SensorEvent};
use windows::Win32::Foundation::ERROR_NO_MORE_FILES;
use windows::Win32::System::Diagnostics::Etw::{CONTROLTRACE_HANDLE, EVENT_TRACE_LOGFILEW};
use crate::dns_cache::DnsResolutionCache;
use crate::path_norm::DosVolumeMap;
use crate::SensorError;

fn assert_snapshot_contains_current_process(events: &[SensorEvent], source: &str) {
    let current_pid = std::process::id();
    assert!(
        !events.is_empty(),
        "{source}: expected Toolhelp32 snapshot to list running processes"
    );

    let current_entry = events.iter().find_map(|event| match event {
        SensorEvent::ProcessStart {
            identity, exe_path, ..
        } if identity.pid == current_pid => Some((identity, exe_path)),
        _ => None,
    });

    let (identity, exe_path) =
        current_entry.unwrap_or_else(|| panic!("current PID must appear in {source}"));
    assert!(
        identity.create_time_100ns > 0,
        "current process create_time_100ns must be > 0"
    );
    assert!(
        !exe_path.is_empty(),
        "current process exe_path must be non-empty"
    );
}

#[test]
fn sens_07_try_capture_running_processes_non_empty() {
    let events = try_capture_running_processes()
        .expect("try_capture_running_processes() must succeed on a live host");
    assert_snapshot_contains_current_process(&events, "try_capture_running_processes()");

    let err = SensorError::Snapshot("enumerated 0 running processes".to_string());
    assert_eq!(
        err.to_string(),
        "process snapshot failed: enumerated 0 running processes"
    );
    assert_eq!(
        windows::core::Error::from(ERROR_NO_MORE_FILES).code(),
        ERROR_NO_MORE_FILES.to_hresult()
    );
}

#[test]
fn sens_08_dns_results_parser_and_noop_backend() {
    let mut noop = NoopSensorBackend;
    assert_eq!(noop.start(), Ok(()));
    assert_eq!(noop.stop(), Ok(()));

    let parsed = parse_dns_query_results(
        "type:  1 93.184.216.34;type: 28 2606:2800:220:1:248:1893:25c8:1946;",
    );
    assert_eq!(
        parsed,
        vec![
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            IpAddr::V6(Ipv6Addr::new(
                0x2606, 0x2800, 0x0220, 0x0001, 0x0248, 0x1893, 0x25c8, 0x1946
            )),
        ]
    );
}

#[test]
fn sens_06_custom_sink_and_graceful_stop_drain() {
    let captured = Arc::new(Mutex::new(Vec::<SensorEvent>::new()));
    let sink_open = Arc::new(AtomicBool::new(true));
    let captured_clone = Arc::clone(&captured);
    let sink_open_clone = Arc::clone(&sink_open);

    let sink: EventSinkFn = Arc::new(move |event| {
        if !sink_open_clone.load(Ordering::Acquire) {
            return false;
        }
        captured_clone
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(event);
        true
    });

    let mut sensor = WindowsEtwSensor::with_sink(sink, "LocalEDR-Custom-Sink-Test");
    assert_eq!(sensor.session_name(), "LocalEDR-Custom-Sink-Test");
    assert_eq!(sensor.stop(), Ok(()));

    // Backwards-compatible mpsc::Sender constructors delegate to the EventSinkFn path.
    let (tx, rx) = mpsc::channel();
    let legacy_sensor = WindowsEtwSensor::new(tx);
    assert_eq!(legacy_sensor.session_name(), DEFAULT_ETW_SESSION_NAME);
    let sample_start = SensorEvent::ProcessStart {
        identity: ProcessIdentity::new(4242, 123_456),
        parent_pid: 4,
        exe_path: "C:\\Windows\\System32\\cmd.exe".to_string(),
        command_line: "cmd.exe /c echo ok".to_string(),
        user_sid: None,
    };
    assert!((legacy_sensor.sink)(sample_start.clone()));
    assert!(rx.try_recv().is_ok());
    drop(rx);
    assert!(!(legacy_sensor.sink)(sample_start.clone()));

    let (tx2, _rx2) = mpsc::channel();
    let named_legacy = WindowsEtwSensor::with_session_name(tx2, "LocalEDR-Legacy-Named");
    assert_eq!(named_legacy.session_name(), "LocalEDR-Legacy-Named");

    // Verify graceful stop() does NOT set stop_requested before draining flushed buffers.
    let stop_requested = Arc::new(AtomicBool::new(false));
    let session_name_nul: Vec<u16> =
        format!("LocalEDR-UnitTest-Drain-{}", std::process::id())
            .encode_utf16()
            .chain(std::iter::once(0u16))
            .collect();

    let worker_ctx = EtwCallbackContext {
        sink: Arc::clone(&sensor.sink),
        dns_cache: Mutex::new(DnsResolutionCache::default()),
        volume_map: DosVolumeMap::with_mappings(Vec::new()),
        canary_matcher: Arc::new(RwLock::new(CanaryMatcher::default())),
        honeypot_handles: Mutex::new(HoneypotHandleTracker::default()),
        has_honeypot_handles: AtomicBool::new(false),
        registry_kcb_names: Mutex::new(HashMap::new()),
        cmdline_correlator: Arc::new(Mutex::new(ProcessCommandLineCorrelator::new())),
        aux_active: AtomicBool::new(false).into(),
        stop_requested: Arc::clone(&stop_requested),
        session_name_nul: session_name_nul.clone(),
    };
    let flushed_start = sample_start.clone();
    let flushed_dns = SensorEvent::DnsQuery {
        pid: 4242,
        query_name: "example.com".to_string(),
        query_type: 1,
        resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
        timestamp_ms: 1_700_000_000_000,
    };
    let worker = thread::spawn(move || {
        thread::sleep(std::time::Duration::from_millis(20));
        let mut ctx_box = Box::new(worker_ctx);
        let mut logfile = EVENT_TRACE_LOGFILEW {
            Context: (&mut *ctx_box as *mut EtwCallbackContext).cast::<c_void>(),
            ..Default::default()
        };
        // SAFETY: `logfile.Context` points to live `ctx_box`.
        assert_eq!(unsafe { buffer_callback(&mut logfile) }, 1);
        assert!(ctx_box.dispatch_event(flushed_start));
        assert!(ctx_box.dispatch_event(flushed_dns));
        assert_eq!(unsafe { buffer_callback(&mut logfile) }, 1);
    });

    {
        let mut guard = sensor.state.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(ActiveEtwSession {
            session_handle: CONTROLTRACE_HANDLE::default(),
            session_name_nul: session_name_nul.clone(),
            stop_requested: Arc::clone(&stop_requested),
            shutdown_initiated: Arc::new(AtomicBool::new(false)),
            aux_active: Arc::new(AtomicBool::new(false)),
            worker: Some(worker),
            aux_session: None,
        });
    }

    assert_eq!(sensor.stop(), Ok(()));
    assert!(
        !stop_requested.load(Ordering::Acquire),
        "graceful stop() must leave stop_requested false while draining flushed buffers"
    );
    assert_eq!(
        captured
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len(),
        2,
        "all flushed events must be delivered during graceful stop()"
    );

    // Verify stop_requested flips to true ONLY once the downstream sink returns false.
    let mut post_ctx = Box::new(EtwCallbackContext {
        sink: Arc::clone(&sensor.sink),
        dns_cache: Mutex::new(DnsResolutionCache::default()),
        volume_map: DosVolumeMap::with_mappings(Vec::new()),
        canary_matcher: Arc::new(RwLock::new(CanaryMatcher::default())),
        honeypot_handles: Mutex::new(HoneypotHandleTracker::default()),
        has_honeypot_handles: AtomicBool::new(false),
        registry_kcb_names: Mutex::new(HashMap::new()),
        cmdline_correlator: Arc::new(Mutex::new(ProcessCommandLineCorrelator::new())),
        aux_active: Arc::new(AtomicBool::new(false)),
        stop_requested: Arc::clone(&stop_requested),
        session_name_nul: session_name_nul.clone(),
    });
    let mut post_logfile = EVENT_TRACE_LOGFILEW {
        Context: (&mut *post_ctx as *mut EtwCallbackContext).cast::<c_void>(),
        ..Default::default()
    };
    // SAFETY: `post_logfile.Context` points to live `post_ctx`.
    assert_eq!(unsafe { buffer_callback(&mut post_logfile) }, 1);

    sink_open.store(false, Ordering::Release);
    assert!(!post_ctx.dispatch_event(sample_start.clone()));
    assert!(
        stop_requested.load(Ordering::Acquire),
        "stop_requested must flip true once downstream sink returns false"
    );
    // SAFETY: `post_logfile.Context` points to live `post_ctx`.
    assert_eq!(
        unsafe { buffer_callback(&mut post_logfile) },
        0,
        "buffer_callback must return 0 once downstream sink closed"
    );

    // Even if the sink flag flips back, dispatch_event stays latched closed.
    sink_open.store(true, Ordering::Release);
    assert!(!post_ctx.dispatch_event(sample_start));
    assert_eq!(
        captured
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len(),
        2
    );

    // Verify explicit force_abort() sets stop_requested before joining worker.
    let abort_flag = Arc::new(AtomicBool::new(false));
    {
        let mut guard = sensor.state.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(ActiveEtwSession {
            session_handle: CONTROLTRACE_HANDLE::default(),
            session_name_nul,
            stop_requested: Arc::clone(&abort_flag),
            shutdown_initiated: Arc::new(AtomicBool::new(false)),
            aux_active: Arc::new(AtomicBool::new(false)),
            worker: Some(thread::spawn(|| {})),
            aux_session: None,
        });
    }
    sensor.force_abort();
    assert!(abort_flag.load(Ordering::Acquire));
}

#[test]
fn sens_p2_14_canary_config_tdh_bytes_and_honeypot_tracker() {
    use windows::Win32::System::Diagnostics::Etw::TDH_INTYPE_UNICODESTRING;

    let (tx, _rx) = mpsc::channel();
    let sensor = WindowsEtwSensor::new(tx)
        .with_dev_roots(vec![PathBuf::from(r"D:\Code\secret")])
        .with_honeypot_paths(vec![PathBuf::from(r"D:\Decoy\trap.docx")]);
    let matcher = sensor.canary_matcher();
    assert_eq!(matcher.dev_root_count(), 1);
    assert_eq!(matcher.honeypot_path_count(), 1);

    let vmap = DosVolumeMap::with_mappings(vec![(
        r"\Device\HarddiskVolume4".encode_utf16().collect(),
        "D:".to_string(),
    )]);

    let to_utf16_bytes = |s: &str| -> Vec<u8> {
        let mut out = Vec::new();
        for unit in s.encode_utf16().chain(std::iter::once(0u16)) {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out
    };

    let benign_bytes = to_utf16_bytes(r"\Device\HarddiskVolume4\Windows\System32\ntdll.dll");
    assert_eq!(
        tdh::inspect_and_classify_canary_bytes(
            &benign_bytes,
            TDH_INTYPE_UNICODESTRING.0 as u16,
            &matcher,
            &vmap,
            false,
        ),
        None
    );

    let env_bytes = to_utf16_bytes(r"\Device\HarddiskVolume4\Code\secret\.env.prod");
    assert_eq!(
        tdh::inspect_and_classify_canary_bytes(
            &env_bytes,
            TDH_INTYPE_UNICODESTRING.0 as u16,
            &matcher,
            &vmap,
            false,
        ),
        Some((CanaryCategory::EnvFile, r"D:\Code\secret\.env.prod".to_string()))
    );

    // Verify FileObject tracking only triggers once on write/delete and clears on close.
    let mut tracker = HoneypotHandleTracker::default();
    assert!(tracker.track_open(0xABCD, r"C:\Users\alice\Documents\!00.docx".to_string()));
    assert_eq!(
        tracker.trigger_write_or_delete(0xABCD),
        Some(r"C:\Users\alice\Documents\!00.docx".to_string())
    );
    assert_eq!(tracker.trigger_write_or_delete(0xABCD), None);
    assert!(!tracker.close_handle(0xABCD));
}

fn registry_facts(
    event_id: u16,
    key_object: u64,
    key_name: RegistryKeyName,
    status: u32,
) -> RegistryEventFacts {
    RegistryEventFacts {
        pid: 4242,
        event_id,
        key_object: Some(key_object),
        status: Some(status),
        key_name,
        disposition: None,
        access_type: None,
        timestamp_ms: 1_700_000_000_000,
    }
}

fn autorun_run_key() -> RegistryKeyName {
    RegistryKeyName::AutorunValue(
        r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run".to_string(),
    )
}

#[test]
fn sens_p2_05_registry_recycled_key_object_drops_stale_name() {
    let cache = Mutex::new(HashMap::new());

    // An open of a monitored autorun key binds its name to the KeyObject.
    let open = registry_facts(2, 0x1000, autorun_run_key(), 0);
    assert!(decide_registry_event(&open, &cache, || panic!("unreachable")).is_none());
    assert!(lookup_registry_key(&cache, 0x1000).is_some());

    // The OS recycles the pointer for an unmonitored key: its named open must evict
    // the stale entry instead of leaving the old attribution behind.
    let reopen = registry_facts(2, 0x1000, RegistryKeyName::Unrelated, 0);
    assert!(decide_registry_event(&reopen, &cache, || panic!("unreachable")).is_none());
    assert!(
        lookup_registry_key(&cache, 0x1000).is_none(),
        "reused KeyObject must drop the stale cached name"
    );

    // An empty-name SetValueKey on the recycled object must not inherit the old name.
    let write = registry_facts(5, 0x1000, RegistryKeyName::Missing, 0);
    assert!(decide_registry_event(&write, &cache, || panic!("no alertable path"))
        .is_none());

    // A write event that arrives with a known non-autorun name evicts rather than
    // alerts — and must not even decode the value name.
    let open2 = registry_facts(2, 0x2000, autorun_run_key(), 0);
    assert!(decide_registry_event(&open2, &cache, || panic!("unreachable")).is_none());
    let named_write = registry_facts(5, 0x2000, RegistryKeyName::Unrelated, 0);
    assert!(decide_registry_event(&named_write, &cache, || {
        panic!("ValueName must not be decoded for unmonitored keys")
    })
    .is_none());
    assert!(lookup_registry_key(&cache, 0x2000).is_none());
}

#[test]
fn sens_p2_06_registry_open_then_value_write_alerts() {
    let cache = Mutex::new(HashMap::new());

    // Opening an existing monitored key must not alert (opens are attribution-only).
    let open = registry_facts(2, 0x2000, autorun_run_key(), 0);
    assert!(decide_registry_event(&open, &cache, || panic!("unreachable")).is_none());

    // A subsequent SetValueKey on the same handle arrives with an empty KeyName:
    // attribution comes from the cache and alerts with the value name appended.
    let set_value = registry_facts(5, 0x2000, RegistryKeyName::Missing, 0);
    let event = decide_registry_event(&set_value, &cache, || {
        Some("Persistence".to_string())
    })
    .expect("SetValueKey on a cached autorun key must alert");
    match event {
        SensorEvent::CanaryFileAccess {
            pid,
            target_path,
            category,
            is_write_or_delete,
            ..
        } => {
            assert_eq!(pid, 4242);
            assert_eq!(category, CanaryCategory::AutorunRegistry);
            assert!(target_path.ends_with(r"\Persistence"), "{target_path}");
            assert!(is_write_or_delete);
        }
        other => panic!("expected CanaryFileAccess, got {other:?}"),
    }

    // DeleteValueKey on the same handle also alerts.
    let delete_value = registry_facts(6, 0x2000, RegistryKeyName::Missing, 0);
    assert!(decide_registry_event(&delete_value, &cache, || None).is_some());

    // CloseKey retires the binding; later empty-name writes stay silent.
    let close = registry_facts(13, 0x2000, RegistryKeyName::Missing, 0);
    assert!(decide_registry_event(&close, &cache, || panic!("unreachable")).is_none());
    let after_close = registry_facts(5, 0x2000, RegistryKeyName::Missing, 0);
    assert!(decide_registry_event(&after_close, &cache, || {
        panic!("ValueName must not be decoded after CloseKey eviction")
    })
    .is_none());
}

#[test]
fn sens_p2_07_registry_failed_ops_neither_alert_nor_mutate_cache() {
    let cache = Mutex::new(HashMap::new());
    const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;

    let open = registry_facts(2, 0x3000, autorun_run_key(), 0);
    assert!(decide_registry_event(&open, &cache, || panic!("unreachable")).is_none());

    // Failed SetValueKey / DeleteValueKey on a cached autorun handle must not alert
    // (and must not even decode the value name).
    let failed_set = registry_facts(5, 0x3000, RegistryKeyName::Missing, STATUS_ACCESS_DENIED);
    assert!(decide_registry_event(&failed_set, &cache, || {
        panic!("ValueName must not be decoded for failed ops")
    })
    .is_none());
    let failed_delete_value =
        registry_facts(6, 0x3000, RegistryKeyName::Missing, STATUS_ACCESS_DENIED);
    assert!(decide_registry_event(&failed_delete_value, &cache, || {
        panic!("ValueName must not be decoded for failed ops")
    })
    .is_none());

    // A failed DeleteKey neither alerts nor clears the cached name.
    let failed_delete_key =
        registry_facts(3, 0x3000, RegistryKeyName::Missing, STATUS_ACCESS_DENIED);
    assert!(decide_registry_event(&failed_delete_key, &cache, || {
        panic!("unreachable")
    })
    .is_none());
    assert!(
        lookup_registry_key(&cache, 0x3000).is_some(),
        "failed DeleteKey must keep the cached name"
    );

    // A failed open must not create a cache binding either.
    let failed_open = registry_facts(2, 0x4000, autorun_run_key(), STATUS_ACCESS_DENIED);
    assert!(decide_registry_event(&failed_open, &cache, || panic!("unreachable")).is_none());
    assert!(lookup_registry_key(&cache, 0x4000).is_none());

    // A successful DeleteKey still alerts with the cached name and evicts it.
    let delete_key = registry_facts(3, 0x3000, RegistryKeyName::Missing, 0);
    assert!(decide_registry_event(&delete_key, &cache, || panic!("unreachable")).is_some());
    assert!(lookup_registry_key(&cache, 0x3000).is_none());
}

#[test]
fn sens_p2_08_registry_missing_status_continues_processing() {
    let cache = Mutex::new(HashMap::new());
    let facts_no_status = |event_id: u16, key_object: u64, key_name: RegistryKeyName| {
        RegistryEventFacts {
            pid: 4242,
            event_id,
            key_object: Some(key_object),
            status: None,
            key_name,
            disposition: None,
            access_type: None,
            timestamp_ms: 1_700_000_000_000,
        }
    };

    // OpenKey with status: None still caches the monitored autorun KeyObject.
    let open = facts_no_status(2, 0x5000, autorun_run_key());
    assert!(decide_registry_event(&open, &cache, || panic!("unreachable")).is_none());
    assert!(
        lookup_registry_key(&cache, 0x5000).is_some(),
        "status: None OpenKey must populate KeyObject cache"
    );

    // SetValueKey with status: None and empty KeyName still resolves from cache and alerts.
    let set_val = facts_no_status(5, 0x5000, RegistryKeyName::Missing);
    let ev = decide_registry_event(&set_val, &cache, || Some("AutoStart".to_string()))
        .expect("status: None SetValueKey on cached autorun key must alert");
    match ev {
        SensorEvent::CanaryFileAccess {
            category,
            target_path,
            is_write_or_delete,
            ..
        } => {
            assert_eq!(category, CanaryCategory::AutorunRegistry);
            assert!(target_path.ends_with(r"\AutoStart"), "{target_path}");
            assert!(is_write_or_delete);
        }
        other => panic!("expected CanaryFileAccess, got {other:?}"),
    }

    // DeleteKey with status: None alerts and evicts the cached KeyObject.
    let del_key = facts_no_status(3, 0x5000, RegistryKeyName::Missing);
    assert!(
        decide_registry_event(&del_key, &cache, || panic!("unreachable")).is_some(),
        "status: None DeleteKey must alert"
    );
    assert!(
        lookup_registry_key(&cache, 0x5000).is_none(),
        "status: None DeleteKey must evict KeyObject"
    );

    // CloseKey with status: None invalidates a cached KeyObject cleanly.
    let open2 = facts_no_status(2, 0x6000, autorun_run_key());
    assert!(decide_registry_event(&open2, &cache, || panic!("unreachable")).is_none());
    assert!(lookup_registry_key(&cache, 0x6000).is_some());
    let close = facts_no_status(13, 0x6000, RegistryKeyName::Missing);
    assert!(decide_registry_event(&close, &cache, || panic!("unreachable")).is_none());
    assert!(
        lookup_registry_key(&cache, 0x6000).is_none(),
        "status: None CloseKey must evict KeyObject"
    );
}

#[test]
fn sens_p3_08_etw_per_pid_dns_isolation_and_pid_reuse_eviction() {
    let sink: EventSinkFn = Arc::new(|_| true);
    let ctx = EtwCallbackContext {
        sink,
        dns_cache: Mutex::new(DnsResolutionCache::default()),
        volume_map: DosVolumeMap::with_mappings(Vec::new()),
        canary_matcher: Arc::new(RwLock::new(CanaryMatcher::default())),
        honeypot_handles: Mutex::new(HoneypotHandleTracker::default()),
        has_honeypot_handles: AtomicBool::new(false),
        registry_kcb_names: Mutex::new(HashMap::new()),
        cmdline_correlator: Arc::new(Mutex::new(ProcessCommandLineCorrelator::new())),
        aux_active: Arc::new(AtomicBool::new(false)),
        stop_requested: Arc::new(AtomicBool::new(false)),
        session_name_nul: vec![0],
    };

    let cdn_ip = IpAddr::V4(Ipv4Addr::new(104, 16, 132, 229));
    let v6_ip = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0x6810, 0x84e5));

    // Process 1001 resolves `allowed.example` to `cdn_ip` and `v6_ip`.
    ctx.record_dns_resolution(1001, "allowed.example", &[cdn_ip, v6_ip], 1_700_000_000_000);
    assert_eq!(
        ctx.resolve_network_domain_hint(1001, &cdn_ip),
        Some("allowed.example".to_string())
    );

    // Process 2002 connecting to the same shared CDN IP MUST NOT inherit 1001's domain hint.
    assert_eq!(
        ctx.resolve_network_domain_hint(2002, &cdn_ip),
        None,
        "cross-PID DNS hint leakage must not occur"
    );

    // Process 2002 resolving `blocked.example` to the same IP stays scoped to 2002 only.
    ctx.record_dns_resolution(2002, "blocked.example", &[cdn_ip], 1_700_000_000_500);
    assert_eq!(
        ctx.resolve_network_domain_hint(2002, &cdn_ip),
        Some("blocked.example".to_string())
    );
    assert_eq!(
        ctx.resolve_network_domain_hint(1001, &cdn_ip),
        Some("allowed.example".to_string())
    );

    // ProcessStop / ProcessStart evicts stale DNS history before PID reuse.
    ctx.evict_dns_pid(1001);
    assert_eq!(ctx.resolve_network_domain_hint(1001, &cdn_ip), None);
    assert_eq!(ctx.resolve_network_domain_hint(1001, &v6_ip), None);
    // PID 2002's entries remain untouched.
    assert_eq!(
        ctx.resolve_network_domain_hint(2002, &cdn_ip),
        Some("blocked.example".to_string())
    );
}

#[test]
fn sens_p3_13_inspect_live_process_rejects_low_bit_pid_aliases() {
    let self_pid = std::process::id();
    let self_info = inspect_live_process(self_pid)
        .expect("inspect_live_process must resolve the current live process");
    assert!(self_info.create_time_100ns > 0);
    assert!(
        self_info
            .exe_path
            .as_deref()
            .is_some_and(|p| !p.trim().is_empty()),
        "current live process must report a non-empty exe_path"
    );

    assert!(
        inspect_live_process(0).is_none(),
        "PID 0 must never resolve via inspect_live_process"
    );

    // Windows OpenProcess masks off the low 2 bits (`pid & !3`), so `self_pid + 1..=3`
    // would otherwise silently open `self_pid` and return its metadata under a forged PID.
    for offset in 1..=3u32 {
        let alias_pid = self_pid.saturating_add(offset);
        assert!(
            inspect_live_process(alias_pid).is_none(),
            "inspect_live_process must reject low-bit PID alias {alias_pid} for live PID {self_pid}"
        );
    }
}
