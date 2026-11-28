use super::*;
use super::net_events::{
    NetEventCallbackContext, NetEventSubscription, NetEventSubscriptionState, wfp_net_event_callback,
};
use std::collections::HashMap;
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_NET_EVENT2, FWPM_NET_EVENT_CLASSIFY_DROP2, FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET,
    FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET, FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET,
    FWPM_NET_EVENT_HEADER2, FWPM_NET_EVENT_TYPE_CLASSIFY_DROP, FWP_IP_VERSION_V4,
    FWP_IP_VERSION_V6,
};

#[derive(Default)]
struct MockWfpState {
    dynamic_session: bool,
    in_tx: bool,
    committed_filters: HashMap<u64, WfpFilterSpec>,
    pending_adds: Vec<(u64, WfpFilterSpec)>,
    pending_deletes: Vec<u64>,
    next_os_id: u64,
    fail_on_layer: Option<WfpLayer>,
    fail_delete_os_id: Option<u64>,
    tx_aborts: usize,
    tx_commits: usize,
    drop_filter_index: Option<Arc<RwLock<HashMap<u64, WfpFilterMeta>>>>,
    drop_sink: Option<WfpDropSinkFn>,
    set_drop_sink_calls: usize,
}

struct MockWfpBackend {
    shared: Arc<Mutex<MockWfpState>>,
}

impl MockWfpBackend {
    fn new_dynamic() -> (Self, Arc<Mutex<MockWfpState>>) {
        let shared = Arc::new(Mutex::new(MockWfpState {
            dynamic_session: true,
            next_os_id: 100,
            ..Default::default()
        }));
        (
            Self {
                shared: Arc::clone(&shared),
            },
            shared,
        )
    }
}

impl WfpBackend for MockWfpBackend {
    fn begin_transaction(&mut self) -> Result<(), String> {
        let mut s = self.shared.lock().unwrap();
        assert!(!s.in_tx, "nested WFP transactions not allowed");
        s.in_tx = true;
        s.pending_adds.clear();
        s.pending_deletes.clear();
        Ok(())
    }

    fn commit_transaction(&mut self) -> Result<(), String> {
        let mut s = self.shared.lock().unwrap();
        assert!(s.in_tx, "commit without active transaction");
        let adds = std::mem::take(&mut s.pending_adds);
        let deletes = std::mem::take(&mut s.pending_deletes);
        for (id, spec) in adds {
            s.committed_filters.insert(id, spec);
        }
        for id in deletes {
            s.committed_filters.remove(&id);
        }
        s.in_tx = false;
        s.tx_commits += 1;
        Ok(())
    }

    fn abort_transaction(&mut self) {
        let mut s = self.shared.lock().unwrap();
        s.pending_adds.clear();
        s.pending_deletes.clear();
        s.in_tx = false;
        s.tx_aborts += 1;
    }

    fn add_filter(&mut self, spec: &WfpFilterSpec) -> Result<u64, String> {
        let mut s = self.shared.lock().unwrap();
        assert!(s.in_tx, "add_filter must run inside a WFP transaction");
        if s.fail_on_layer == Some(spec.layer) {
            return Err(format!("injected WFP failure on {:?}", spec.layer));
        }
        let id = s.next_os_id;
        s.next_os_id += 1;
        s.pending_adds.push((id, spec.clone()));
        Ok(id)
    }

    fn delete_filter(&mut self, os_filter_id: u64) -> Result<(), String> {
        let mut s = self.shared.lock().unwrap();
        assert!(s.in_tx, "delete_filter must run inside a WFP transaction");
        if s.fail_delete_os_id == Some(os_filter_id) {
            return Err(format!("injected delete failure for {os_filter_id}"));
        }
        s.pending_deletes.push(os_filter_id);
        Ok(())
    }

    fn is_dynamic_session(&self) -> bool {
        self.shared.lock().unwrap().dynamic_session
    }

    fn set_drop_sink(
        &mut self,
        filter_index: Arc<RwLock<HashMap<u64, WfpFilterMeta>>>,
        sink: Option<WfpDropSinkFn>,
    ) -> Result<(), String> {
        let mut s = self.shared.lock().unwrap();
        s.drop_filter_index = Some(filter_index);
        s.drop_sink = sink;
        s.set_drop_sink_calls += 1;
        Ok(())
    }
}

#[test]
fn sens_p3_01_wfp_dynamic_session_enforced_and_never_block_guard() {
    let non_dynamic = MockWfpBackend {
        shared: Arc::new(Mutex::new(MockWfpState {
            dynamic_session: false,
            ..Default::default()
        })),
    };
    assert!(
        WfpDynamicEngine::from_backend(Box::new(non_dynamic)).is_err(),
        "AUTO-04: engine must reject non-dynamic WFP sessions"
    );

    let (backend, state) = MockWfpBackend::new_dynamic();
    let engine = WfpDynamicEngine::from_backend(Box::new(backend)).expect("dynamic engine");

    // Never-Block guard (`AUTO-02`): protected OS and LocalEDR binaries cannot be blocked.
    for protected in [
        r"C:\Windows\System32\lsass.exe",
        r"C:\Windows\System32\svchost.exe",
        r"C:\Windows\explorer.exe",
        r"C:\Program Files\LocalEDR\ledr-daemon.exe",
        r"C:\Program Files\LocalEDR\ledr-ui.exe",
    ] {
        let err = engine
            .add_app_rule(Path::new(protected), None, false)
            .expect_err("protected binary must reject WFP block");
        assert!(err.contains("protected process"), "{err}");
    }

    // Empty and wildcard paths are rejected cleanly.
    assert!(engine.add_app_rule(Path::new(""), None, false).is_err());
    assert!(engine
        .add_app_rule(Path::new(r"C:\Users\*\Downloads\*.exe"), None, false)
        .is_err());
    assert_eq!(state.lock().unwrap().committed_filters.len(), 0);
}

#[test]
fn sens_p3_02_dual_stack_atomic_registration_and_rollback_on_v6_failure() {
    let (backend, state) = MockWfpBackend::new_dynamic();
    let engine = WfpDynamicEngine::from_backend(Box::new(backend)).expect("dynamic engine");

    // Inject IPv6 filter failure after IPv4 succeeds -> entire transaction must roll back!
    state.lock().unwrap().fail_on_layer = Some(WfpLayer::AleAuthConnectV6);
    let err = engine
        .add_app_rule(Path::new(r"C:\Temp\dropper.exe"), None, false)
        .expect_err("IPv6 failure must fail dual-stack add");
    assert!(err.contains("AleAuthConnectV6"), "{err}");
    assert_eq!(engine.active_handle_count(), 0);
    {
        let s = state.lock().unwrap();
        assert!(
            s.committed_filters.is_empty(),
            "atomic rollback must leave zero committed IPv4 filters"
        );
        assert_eq!(s.tx_aborts, 1);
    }

    // Clear fault injection -> app-wide rule registers BOTH IPv4 and IPv6 under 1 opaque handle.
    state.lock().unwrap().fail_on_layer = None;
    let handle = engine
        .add_app_rule(Path::new(r"\\?\C:/Temp/dropper.exe"), None, false)
        .expect("dual-stack add succeeds");
    assert_ne!(handle, 0);
    assert_eq!(engine.active_handle_count(), 1);
    let os_ids = engine
        .os_filter_ids_for_handle(handle)
        .expect("handle mapped");
    assert_eq!(os_ids.len(), 2, "dual-stack rule must map to 2 OS filters");

    {
        let s = state.lock().unwrap();
        assert_eq!(s.committed_filters.len(), 2);
        let f0 = &s.committed_filters[&os_ids[0]];
        let f1 = &s.committed_filters[&os_ids[1]];
        assert_eq!(f0.layer, WfpLayer::AleAuthConnectV4);
        assert_eq!(f1.layer, WfpLayer::AleAuthConnectV6);
        assert_eq!(f0.exe_path, r"C:\Temp\dropper.exe");
        assert_eq!(f0.sublayer_guid, LEDR_WFP_SUBLAYER_GUID);
        assert_eq!(f0.provider_guid, LEDR_WFP_PROVIDER_GUID);
        assert_eq!(f0.action, WfpFilterAction::Block);
        assert_eq!(f0.weight, WFP_WEIGHT_BLOCK_APP);
        assert!(f0.dynamic_session_required);
    }

    // Removing the opaque handle atomically deletes BOTH OS filters.
    engine.remove_rule(handle).expect("dual-stack remove succeeds");
    assert_eq!(engine.active_handle_count(), 0);
    assert!(state.lock().unwrap().committed_filters.is_empty());
    assert!(engine.remove_rule(handle).is_err());
    assert!(engine.remove_rule(0).is_err());
}

#[test]
fn sens_p3_03_single_stack_ip_encoding_and_weight_precedence() {
    let (backend, state) = MockWfpBackend::new_dynamic();
    let engine = WfpDynamicEngine::from_backend(Box::new(backend)).expect("dynamic engine");

    let v4 = Ipv4Addr::new(93, 184, 216, 34);
    let v6 = Ipv6Addr::new(0x2606, 0x2800, 0x0220, 0x0001, 0x0248, 0x1893, 0x25c8, 0x1946);

    let h_v4_permit = engine
        .add_app_rule(Path::new(r"C:\Tools\app.exe"), Some(IpAddr::V4(v4)), true)
        .expect("v4 permit");
    let h_v6_block = engine
        .add_app_rule(Path::new(r"C:\Tools\app.exe"), Some(IpAddr::V6(v6)), false)
        .expect("v6 block");
    let h_app_permit = engine
        .add_app_rule(Path::new(r"C:\Tools\app.exe"), None, true)
        .expect("app permit");

    let id_v4 = engine.os_filter_ids_for_handle(h_v4_permit).unwrap();
    let id_v6 = engine.os_filter_ids_for_handle(h_v6_block).unwrap();
    let id_app = engine.os_filter_ids_for_handle(h_app_permit).unwrap();
    assert_eq!(id_v4.len(), 1);
    assert_eq!(id_v6.len(), 1);
    assert_eq!(id_app.len(), 2);

    {
        let s = state.lock().unwrap();
        let v4_spec = &s.committed_filters[&id_v4[0]];
        assert_eq!(v4_spec.layer, WfpLayer::AleAuthConnectV4);
        assert_eq!(
            v4_spec.remote_addr,
            Some(WfpRemoteAddress::V4HostOrder(0x5DB8_D822))
        );
        assert_eq!(v4_spec.action, WfpFilterAction::Permit);
        assert_eq!(v4_spec.weight, WFP_WEIGHT_PERMIT_SPECIFIC);

        let v6_spec = &s.committed_filters[&id_v6[0]];
        assert_eq!(v6_spec.layer, WfpLayer::AleAuthConnectV6);
        assert_eq!(
            v6_spec.remote_addr,
            Some(WfpRemoteAddress::V6NetworkOrder(v6.octets()))
        );
        assert_eq!(v6_spec.action, WfpFilterAction::Block);
        assert_eq!(v6_spec.weight, WFP_WEIGHT_BLOCK_SPECIFIC);

        let app_permit_spec = &s.committed_filters[&id_app[0]];
        assert_eq!(app_permit_spec.weight, WFP_WEIGHT_PERMIT_APP);
    }

    // Verify strict weight hierarchy:
    // loopback permit (15) > specific block (14) > specific permit (13) > app block (11) > app permit (10).
    const {
        assert!(WFP_WEIGHT_LOOPBACK_PERMIT > WFP_WEIGHT_BLOCK_SPECIFIC);
        assert!(WFP_WEIGHT_BLOCK_SPECIFIC > WFP_WEIGHT_PERMIT_SPECIFIC);
        assert!(WFP_WEIGHT_PERMIT_SPECIFIC > WFP_WEIGHT_BLOCK_APP);
        assert!(WFP_WEIGHT_BLOCK_APP > WFP_WEIGHT_PERMIT_APP);
    }

    // Delete failure aborts transaction and preserves handle mapping for retry.
    state.lock().unwrap().fail_delete_os_id = Some(id_app[1]);
    assert!(engine.remove_rule(h_app_permit).is_err());
    assert!(engine.os_filter_ids_for_handle(h_app_permit).is_some());
    assert_eq!(state.lock().unwrap().committed_filters.len(), 4);

    state.lock().unwrap().fail_delete_os_id = None;
    engine
        .remove_rule(h_app_permit)
        .expect("retry remove succeeds");
    assert_eq!(state.lock().unwrap().committed_filters.len(), 2);
}

#[test]
fn sens_p3_05_ipv4_mapped_ipv6_routes_to_v4_layer_and_trailing_dot_never_block() {
    let (backend, state) = MockWfpBackend::new_dynamic();
    let engine = WfpDynamicEngine::from_backend(Box::new(backend)).expect("dynamic engine");

    // IPv4-mapped IPv6 address must route to ALE_AUTH_CONNECT_V4 with host-order IPv4.
    let mapped_v6 = Ipv4Addr::new(93, 184, 216, 34).to_ipv6_mapped();
    let handle = engine
        .add_app_rule(Path::new(r"C:\Tools\dualstack.exe"), Some(IpAddr::V6(mapped_v6)), false)
        .expect("mapped v6 rule");
    let os_ids = engine.os_filter_ids_for_handle(handle).expect("mapped");
    assert_eq!(os_ids.len(), 1);
    {
        let s = state.lock().unwrap();
        let spec = &s.committed_filters[&os_ids[0]];
        assert_eq!(spec.layer, WfpLayer::AleAuthConnectV4);
        assert_eq!(
            spec.remote_addr,
            Some(WfpRemoteAddress::V4HostOrder(0x5DB8_D822))
        );
    }

    // Trailing-dot Windows path alias for protected process must still be rejected.
    let err = engine
        .add_app_rule(Path::new(r"C:\Windows\System32\lsass.exe."), None, false)
        .expect_err("trailing-dot lsass.exe. must be refused");
    assert!(err.contains("protected process"), "{err}");
}

/// `SENS-P3-06`: Loopback Permit specs (`127.0.0.0/8` and `::1/128`) use exact WFP mask/prefix
/// encoding, non-persistent dynamic flags without `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`, and
/// strict SubLayer weight hierarchy `15 > 14 > 13 > 11 > 10`.
#[test]
fn sens_p3_06_loopback_permit_specs_and_weight_hierarchy() {
    let specs = build_loopback_permit_filter_specs();
    assert_eq!(specs.len(), 2);

    let v4 = &specs[0];
    assert_eq!(v4.layer, WfpLayer::AleAuthConnectV4);
    assert_eq!(v4.sublayer_guid, LEDR_WFP_SUBLAYER_GUID);
    assert_eq!(v4.provider_guid, LEDR_WFP_PROVIDER_GUID);
    assert_eq!(v4.action, WfpFilterAction::Permit);
    assert_eq!(v4.weight, WFP_WEIGHT_LOOPBACK_PERMIT);
    assert_eq!(v4.weight, 15);
    assert!(!v4.persistent);
    assert!(!v4.clear_action_right);
    assert!(v4.dynamic_session_required);
    match v4.condition {
        WfpLoopbackCondition::V4AddrMask { addr, mask } => {
            assert_eq!(addr, 0x7F00_0000);
            assert_eq!(mask, 0xFF00_0000);
            // Verify 127.0.0.0/8 matches loopback addresses and excludes external addresses.
            assert_eq!(ipv4_to_wfp_host_order(Ipv4Addr::new(127, 0, 0, 1)) & mask, addr);
            assert_eq!(
                ipv4_to_wfp_host_order(Ipv4Addr::new(127, 255, 255, 254)) & mask,
                addr
            );
            assert_ne!(ipv4_to_wfp_host_order(Ipv4Addr::new(128, 0, 0, 1)) & mask, addr);
            assert_ne!(
                ipv4_to_wfp_host_order(Ipv4Addr::new(93, 184, 216, 34)) & mask,
                addr
            );
        }
        other => panic!("expected V4AddrMask, got {other:?}"),
    }

    let v6 = &specs[1];
    assert_eq!(v6.layer, WfpLayer::AleAuthConnectV6);
    assert_eq!(v6.sublayer_guid, LEDR_WFP_SUBLAYER_GUID);
    assert_eq!(v6.provider_guid, LEDR_WFP_PROVIDER_GUID);
    assert_eq!(v6.action, WfpFilterAction::Permit);
    assert_eq!(v6.weight, WFP_WEIGHT_LOOPBACK_PERMIT);
    assert!(!v6.persistent);
    assert!(!v6.clear_action_right);
    assert!(v6.dynamic_session_required);
    assert_eq!(
        v6.condition,
        WfpLoopbackCondition::V6AddrMask {
            addr: ipv6_to_wfp_network_order(Ipv6Addr::LOCALHOST),
            prefix_length: 128,
        }
    );

    assert_eq!(WFP_WEIGHT_LOOPBACK_PERMIT, 15);
    assert_eq!(WFP_WEIGHT_BLOCK_SPECIFIC, 14);
    assert_eq!(WFP_WEIGHT_PERMIT_SPECIFIC, 13);
    assert_eq!(WFP_WEIGHT_BLOCK_APP, 11);
    assert_eq!(WFP_WEIGHT_PERMIT_APP, 10);
    const {
        assert!(WFP_WEIGHT_LOOPBACK_PERMIT > WFP_WEIGHT_BLOCK_SPECIFIC);
        assert!(WFP_WEIGHT_BLOCK_SPECIFIC > WFP_WEIGHT_PERMIT_SPECIFIC);
        assert!(WFP_WEIGHT_PERMIT_SPECIFIC > WFP_WEIGHT_BLOCK_APP);
        assert!(WFP_WEIGHT_BLOCK_APP > WFP_WEIGHT_PERMIT_APP);
    }
}

#[test]
fn sens_p3_09_parse_wfp_classify_drop_fields_v4_v6_flags_and_filter_matching() {
    use windows::core::BOOL;
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FWPM_NET_EVENT_HEADER2_1, FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW, FWP_BYTE_ARRAY16,
        FWP_IP_VERSION_NONE,
    };

    const UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
    let expected_ts_ms: i64 = 1_760_123_456_789;
    let ft_100ns = UNIX_EPOCH_100NS + (expected_ts_ms as u64) * 10_000;
    let ts = FILETIME {
        dwLowDateTime: ft_100ns as u32,
        dwHighDateTime: (ft_100ns >> 32) as u32,
    };

    let mut filter_index = HashMap::new();
    filter_index.insert(
        7001,
        WfpFilterMeta {
            rule_handle: 11,
            exe_path: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
            allow: false,
        },
    );
    filter_index.insert(
        7002,
        WfpFilterMeta {
            rule_handle: 12,
            exe_path: r"C:\Tools\allowed.exe".to_string(),
            allow: true,
        },
    );

    let v4_header = FWPM_NET_EVENT_HEADER2 {
        timeStamp: ts,
        flags: FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET
            | FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET
            | FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET,
        ipVersion: FWP_IP_VERSION_V4,
        ipProtocol: 6,
        Anonymous2: FWPM_NET_EVENT_HEADER2_1 {
            remoteAddrV4: 0x5DB8_D822, // 93.184.216.34 in host byte order
        },
        remotePort: 443,
        ..Default::default()
    };
    let v4_drop = FWPM_NET_EVENT_CLASSIFY_DROP2 {
        filterId: 7001,
        isLoopback: BOOL(0),
        ..Default::default()
    };

    // 1. Valid IPv4 non-loopback drop on a LocalEDR block filter emits WfpDropEvent.
    let parsed_v4 = parse_wfp_classify_drop_fields(
        FWPM_NET_EVENT_TYPE_CLASSIFY_DROP,
        &v4_header,
        Some(&v4_drop),
        &filter_index,
    )
    .expect("expected valid IPv4 WfpDropEvent");
    assert_eq!(
        parsed_v4,
        WfpDropEvent {
            os_filter_id: 7001,
            rule_handle: 11,
            exe_path: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            dst_port: 443,
            timestamp_ms: expected_ts_ms,
            package_sid: None,
        }
    );

    // 2. Valid IPv6 non-loopback drop decodes `[u8; 16]` network-order IP and host-order port.
    let v6 = Ipv6Addr::new(0x2606, 0x2800, 0x0220, 0x0001, 0x0248, 0x1893, 0x25c8, 0x1946);
    let v6_header = FWPM_NET_EVENT_HEADER2 {
        timeStamp: ts,
        flags: FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET
            | FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET
            | FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET,
        ipVersion: FWP_IP_VERSION_V6,
        ipProtocol: 17,
        Anonymous2: FWPM_NET_EVENT_HEADER2_1 {
            remoteAddrV6: FWP_BYTE_ARRAY16 {
                byteArray16: v6.octets(),
            },
        },
        remotePort: 8443,
        ..Default::default()
    };
    let parsed_v6 = parse_wfp_classify_drop_fields(
        FWPM_NET_EVENT_TYPE_CLASSIFY_DROP,
        &v6_header,
        Some(&v4_drop),
        &filter_index,
    )
    .expect("expected valid IPv6 WfpDropEvent");
    assert_eq!(parsed_v6.dst_ip, IpAddr::V6(v6));
    assert_eq!(parsed_v6.protocol, 17);
    assert_eq!(parsed_v6.dst_port, 8443);

    // 3. Loopback drops, non-drop types, missing payload, unknown filters, and allow filters are ignored.
    let loopback_drop = FWPM_NET_EVENT_CLASSIFY_DROP2 {
        filterId: 7001,
        isLoopback: BOOL(1),
        ..Default::default()
    };
    assert_eq!(
        parse_wfp_classify_drop_fields(
            FWPM_NET_EVENT_TYPE_CLASSIFY_DROP,
            &v4_header,
            Some(&loopback_drop),
            &filter_index,
        ),
        None
    );
    assert_eq!(
        parse_wfp_classify_drop_fields(
            FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW,
            &v4_header,
            Some(&v4_drop),
            &filter_index,
        ),
        None
    );
    assert_eq!(
        parse_wfp_classify_drop_fields(
            FWPM_NET_EVENT_TYPE_CLASSIFY_DROP,
            &v4_header,
            None,
            &filter_index,
        ),
        None
    );
    let other_app_drop = FWPM_NET_EVENT_CLASSIFY_DROP2 {
        filterId: 9999,
        isLoopback: BOOL(0),
        ..Default::default()
    };
    assert_eq!(
        parse_wfp_classify_drop_fields(
            FWPM_NET_EVENT_TYPE_CLASSIFY_DROP,
            &v4_header,
            Some(&other_app_drop),
            &filter_index,
        ),
        None
    );
    let permit_filter_drop = FWPM_NET_EVENT_CLASSIFY_DROP2 {
        filterId: 7002,
        isLoopback: BOOL(0),
        ..Default::default()
    };
    assert_eq!(
        parse_wfp_classify_drop_fields(
            FWPM_NET_EVENT_TYPE_CLASSIFY_DROP,
            &v4_header,
            Some(&permit_filter_drop),
            &filter_index,
        ),
        None
    );

    // 4. Missing REMOTE_ADDR_SET or FWP_IP_VERSION_NONE returns None; missing IP_PROTOCOL_SET
    //    or REMOTE_PORT_SET zeroes unflagged protocol/port rather than leaking garbage values.
    let no_addr_hdr = FWPM_NET_EVENT_HEADER2 {
        flags: FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET | FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET,
        ..v4_header
    };
    assert_eq!(
        parse_wfp_classify_drop_fields(
            FWPM_NET_EVENT_TYPE_CLASSIFY_DROP,
            &no_addr_hdr,
            Some(&v4_drop),
            &filter_index,
        ),
        None
    );
    let bad_ver_hdr = FWPM_NET_EVENT_HEADER2 {
        ipVersion: FWP_IP_VERSION_NONE,
        ..v4_header
    };
    assert_eq!(
        parse_wfp_classify_drop_fields(
            FWPM_NET_EVENT_TYPE_CLASSIFY_DROP,
            &bad_ver_hdr,
            Some(&v4_drop),
            &filter_index,
        ),
        None
    );
    let partial_flags_hdr = FWPM_NET_EVENT_HEADER2 {
        flags: FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET,
        ipProtocol: 6,
        remotePort: 443,
        ..v4_header
    };
    let partial = parse_wfp_classify_drop_fields(
        FWPM_NET_EVENT_TYPE_CLASSIFY_DROP,
        &partial_flags_hdr,
        Some(&v4_drop),
        &filter_index,
    )
    .expect("drop without protocol/port flags still extracts remote addr");
    assert_eq!(partial.protocol, 0);
    assert_eq!(partial.dst_port, 0);
    assert_eq!(partial.package_sid, None);

    // 5. Package SID extraction follows `FWPM_NET_EVENT_FLAG_PACKAGE_ID_SET` and non-null `packageSid`.
    {
        use std::ffi::c_void;
        use windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_NET_EVENT_FLAG_PACKAGE_ID_SET;
        use windows::Win32::Security::SID;

        #[link(name = "advapi32")]
        extern "system" {
            fn ConvertStringSidToSidW(string_sid: *const u16, sid: *mut *mut c_void) -> i32;
        }
        #[link(name = "kernel32")]
        extern "system" {
            fn LocalFree(hmem: *mut c_void) -> *mut c_void;
        }
        struct LocalSid(*mut c_void);
        impl Drop for LocalSid {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    // SAFETY: allocated by `ConvertStringSidToSidW`.
                    unsafe {
                        let _ = LocalFree(self.0);
                    }
                }
            }
        }

        let expected_sid = "S-1-15-2-1-2-3-4-5-6-7";
        let wide: Vec<u16> = expected_sid
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut raw_sid: *mut c_void = std::ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated UTF-16; `raw_sid` is freed by `LocalSid`.
        assert_ne!(unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut raw_sid) }, 0);
        let _sid_guard = LocalSid(raw_sid);

        // (a) Flag set + valid AppContainer SID -> extracted.
        let pkg_hdr = FWPM_NET_EVENT_HEADER2 {
            flags: v4_header.flags | FWPM_NET_EVENT_FLAG_PACKAGE_ID_SET,
            packageSid: raw_sid.cast::<SID>(),
            ..v4_header
        };
        let pkg_ev = parse_wfp_classify_drop_fields(
            FWPM_NET_EVENT_TYPE_CLASSIFY_DROP,
            &pkg_hdr,
            Some(&v4_drop),
            &filter_index,
        )
        .expect("drop with packageSid must parse");
        assert_eq!(pkg_ev.package_sid.as_deref(), Some(expected_sid));

        // (b) Flag unset + non-null packageSid -> None.
        let unflagged_hdr = FWPM_NET_EVENT_HEADER2 {
            packageSid: raw_sid.cast::<SID>(),
            ..v4_header
        };
        let unflagged_ev = parse_wfp_classify_drop_fields(
            FWPM_NET_EVENT_TYPE_CLASSIFY_DROP,
            &unflagged_hdr,
            Some(&v4_drop),
            &filter_index,
        )
        .expect("drop without package flag must parse");
        assert_eq!(unflagged_ev.package_sid, None);

        // (c) Flag set + null packageSid -> None.
        let null_sid_hdr = FWPM_NET_EVENT_HEADER2 {
            flags: v4_header.flags | FWPM_NET_EVENT_FLAG_PACKAGE_ID_SET,
            packageSid: std::ptr::null_mut(),
            ..v4_header
        };
        let null_sid_ev = parse_wfp_classify_drop_fields(
            FWPM_NET_EVENT_TYPE_CLASSIFY_DROP,
            &null_sid_hdr,
            Some(&v4_drop),
            &filter_index,
        )
        .expect("drop with null packageSid must parse");
        assert_eq!(null_sid_ev.package_sid, None);
    }
}

#[test]
fn sens_p3_10_wfp_dynamic_engine_filter_index_and_drop_sink_lifecycle() {
    use windows::core::BOOL;
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_NET_EVENT_HEADER2_1;

    let (backend, state) = MockWfpBackend::new_dynamic();
    let engine = WfpDynamicEngine::from_backend(Box::new(backend)).expect("dynamic engine");

    let received = Arc::new(Mutex::new(Vec::<WfpDropEvent>::new()));
    let received_clone = Arc::clone(&received);
    let sink: WfpDropSinkFn = Arc::new(move |ev| {
        received_clone.lock().unwrap().push(ev);
    });
    engine.set_drop_sink(sink).expect("set_drop_sink");

    // Transaction failure must NOT populate `filter_index`.
    state.lock().unwrap().fail_on_layer = Some(WfpLayer::AleAuthConnectV6);
    assert!(engine
        .add_app_rule(Path::new(r"C:\Temp\blocked.exe"), None, false)
        .is_err());
    state.lock().unwrap().fail_on_layer = None;
    assert!(engine.filter_meta(100).is_none());

    // Add dual-stack block rule and single-stack permit rule.
    let block_handle = engine
        .add_app_rule(Path::new(r"\\?\C:/Temp/blocked.exe"), None, false)
        .expect("add block rule");
    let block_os_ids = engine.os_filter_ids_for_handle(block_handle).unwrap();
    assert_eq!(block_os_ids.len(), 2);
    for &os_id in &block_os_ids {
        let meta = engine.filter_meta(os_id).expect("indexed block filter");
        assert_eq!(meta.rule_handle, block_handle);
        assert_eq!(meta.exe_path, r"C:\Temp\blocked.exe");
        assert!(!meta.allow);
    }

    let permit_handle = engine
        .add_app_rule(
            Path::new(r"C:\Temp\allowed.exe"),
            Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
            true,
        )
        .expect("add permit rule");
    let permit_os_ids = engine.os_filter_ids_for_handle(permit_handle).unwrap();
    let permit_meta = engine.filter_meta(permit_os_ids[0]).expect("indexed permit");
    assert!(permit_meta.allow);

    // Simulate BFE callback hitting `filter_index` captured via `set_drop_sink`.
    let (index_arc, active_sink) = {
        let s = state.lock().unwrap();
        (
            s.drop_filter_index.clone().expect("index captured"),
            s.drop_sink.clone().expect("sink captured"),
        )
    };
    let header = FWPM_NET_EVENT_HEADER2 {
        timeStamp: FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        },
        flags: FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET
            | FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET
            | FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET,
        ipVersion: FWP_IP_VERSION_V4,
        ipProtocol: 6,
        Anonymous2: FWPM_NET_EVENT_HEADER2_1 {
            remoteAddrV4: 0x0808_0808,
        },
        remotePort: 443,
        ..Default::default()
    };
    let drop_block = FWPM_NET_EVENT_CLASSIFY_DROP2 {
        filterId: block_os_ids[0],
        isLoopback: BOOL(0),
        ..Default::default()
    };
    let drop_permit = FWPM_NET_EVENT_CLASSIFY_DROP2 {
        filterId: permit_os_ids[0],
        isLoopback: BOOL(0),
        ..Default::default()
    };

    {
        let guard = index_arc.read().unwrap();
        if let Some(ev) = parse_wfp_classify_drop_fields(
            FWPM_NET_EVENT_TYPE_CLASSIFY_DROP,
            &header,
            Some(&drop_block),
            &guard,
        ) {
            active_sink(ev);
        }
        if let Some(ev) = parse_wfp_classify_drop_fields(
            FWPM_NET_EVENT_TYPE_CLASSIFY_DROP,
            &header,
            Some(&drop_permit),
            &guard,
        ) {
            active_sink(ev);
        }
    }

    let captured = received.lock().unwrap();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].os_filter_id, block_os_ids[0]);
    assert_eq!(captured[0].rule_handle, block_handle);
    assert_eq!(captured[0].dst_ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(captured[0].dst_port, 443);
    drop(captured);

    // Removing the block rule removes its OS filter IDs from `filter_index`.
    engine.remove_rule(block_handle).expect("remove block");
    for os_id in &block_os_ids {
        assert!(engine.filter_meta(*os_id).is_none());
    }

    engine.clear_drop_sink().expect("clear_drop_sink");
    let s = state.lock().unwrap();
    assert!(s.drop_sink.is_none());
    assert_eq!(s.set_drop_sink_calls, 2);
}

#[test]
fn sens_p3_12_net_event_unsubscribe_failure_keeps_context_alive_and_gates_callback() {
    use std::sync::atomic::AtomicUsize;
    use windows::core::BOOL;
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FWPM_NET_EVENT2_0, FWPM_NET_EVENT_HEADER2_1,
    };

    struct DropObserver(Arc<AtomicUsize>);
    impl Drop for DropObserver {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let sink_drops = Arc::new(AtomicUsize::new(0));
    let sink_calls = Arc::new(AtomicUsize::new(0));
    let observer = DropObserver(Arc::clone(&sink_drops));
    let sink_calls_ref = Arc::clone(&sink_calls);
    let sink: WfpDropSinkFn = Arc::new(move |_ev| {
        let _keep = &observer;
        sink_calls_ref.fetch_add(1, Ordering::SeqCst);
    });

    let mut map = HashMap::new();
    map.insert(
        555u64,
        WfpFilterMeta {
            rule_handle: 1,
            exe_path: r"C:\Temp\blocked.exe".to_string(),
            allow: false,
        },
    );
    let filter_index = Arc::new(RwLock::new(map));
    let ctx_ptr = Box::into_raw(Box::new(NetEventCallbackContext {
        active: AtomicBool::new(true),
        filter_index,
        sink,
    }));

    let mut drop_data = FWPM_NET_EVENT_CLASSIFY_DROP2 {
        filterId: 555,
        isLoopback: BOOL(0),
        ..Default::default()
    };
    let net_ev = FWPM_NET_EVENT2 {
        header: FWPM_NET_EVENT_HEADER2 {
            timeStamp: FILETIME::default(),
            flags: FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET
                | FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET
                | FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET,
            ipVersion: FWP_IP_VERSION_V4,
            ipProtocol: 6,
            Anonymous2: FWPM_NET_EVENT_HEADER2_1 {
                remoteAddrV4: 0x0101_0101,
            },
            remotePort: 443,
            ..Default::default()
        },
        r#type: FWPM_NET_EVENT_TYPE_CLASSIFY_DROP,
        Anonymous: FWPM_NET_EVENT2_0 {
            classifyDrop: &mut drop_data,
        },
    };

    // 1. Active callback invokes sink before unsubscribe.
    unsafe { wfp_net_event_callback(ctx_ptr.cast(), &net_ev) };
    assert_eq!(sink_calls.load(Ordering::SeqCst), 1);

    let mut state = NetEventSubscriptionState {
        sub: Some(NetEventSubscription {
            events_handle: HANDLE(0x1234usize as *mut c_void),
            ctx_ptr,
        }),
        enabled_net_events_by_us: true,
    };

    // 2. When FwpmNetEventUnsubscribe0 fails, `ctx_ptr` MUST NOT be freed (`sink_drops == 0`),
    //    `sub` stays intact for retry, `COLLECT_NET_EVENTS` disable is skipped, and late
    //    callbacks are suppressed safely via `active == false`.
    let mut disable_calls = 0usize;
    let err = state
        .unsubscribe_with(|_| Err(0x8032_0001), || {
            disable_calls += 1;
            Ok(())
        })
        .expect_err("failed unsubscribe must return Err");
    assert!(err.contains("0x80320001"), "{err}");
    assert!(state.sub.is_some(), "subscription handle must remain for retry");
    assert!(state.enabled_net_events_by_us);
    assert_eq!(disable_calls, 0);
    assert_eq!(sink_drops.load(Ordering::SeqCst), 0);

    unsafe { wfp_net_event_callback(ctx_ptr.cast(), &net_ev) };
    assert_eq!(sink_calls.load(Ordering::SeqCst), 1, "deactivated callback must not invoke sink");

    // 3. If FwpmNetEventUnsubscribe0 later succeeds while disable fails, `ctx_ptr` IS freed
    //    (`sink_drops == 1`) and `enabled_net_events_by_us` remains true for retry.
    let err2 = state
        .unsubscribe_with(|_| Ok(()), || {
            disable_calls += 1;
            Err(0x8032_0005)
        })
        .expect_err("failed disable option must return Err");
    assert!(err2.contains("0x80320005"), "{err2}");
    assert!(state.sub.is_none());
    assert!(state.enabled_net_events_by_us);
    assert_eq!(disable_calls, 1);
    assert_eq!(sink_drops.load(Ordering::SeqCst), 1);

    // 4. Final retry disables COLLECT_NET_EVENTS cleanly.
    state
        .unsubscribe_with(|_| unreachable!(), || {
            disable_calls += 1;
            Ok(())
        })
        .expect("retry disable succeeds");
    assert!(!state.enabled_net_events_by_us);
    assert_eq!(disable_calls, 2);
}

#[test]
fn wfp_fu_p4_03_track_b2_scoped_filter_specs_weights_and_transaction_rollback() {
    use ledr_proto::ActiveDefenseController;
    use std::net::Ipv4Addr;
    use std::path::Path;

    let bth = Path::new(r"C:\Windows\System32\backgroundTaskHost.exe");
    let sid_a = "S-1-15-2-111-222-333";

    // Weight hierarchy: Loopback (15) > Block IP / Package (14 == 14) > Permit IP (13) > Permit Package (12) > Block App (11) > Permit App (10).
    assert_eq!(WFP_WEIGHT_BLOCK_PACKAGE, 14);
    assert_eq!(WFP_WEIGHT_PERMIT_PACKAGE, 12);
    const {
        assert!(WFP_WEIGHT_LOOPBACK_PERMIT > WFP_WEIGHT_BLOCK_PACKAGE);
        assert!(WFP_WEIGHT_BLOCK_PACKAGE == WFP_WEIGHT_BLOCK_SPECIFIC);
        assert!(WFP_WEIGHT_BLOCK_PACKAGE > WFP_WEIGHT_PERMIT_SPECIFIC);
        assert!(WFP_WEIGHT_PERMIT_SPECIFIC > WFP_WEIGHT_PERMIT_PACKAGE);
        assert!(WFP_WEIGHT_PERMIT_PACKAGE > WFP_WEIGHT_BLOCK_APP);
        assert!(WFP_WEIGHT_BLOCK_APP > WFP_WEIGHT_PERMIT_APP);
    }

    // Scoped package-wide Block builds IPv4+IPv6 specs carrying `package_sid` and weight 14.
    let block_specs = build_wfp_scoped_filter_specs(bth, Some(sid_a), None, false)
        .expect("build scoped package-wide block specs");
    assert_eq!(block_specs.len(), 2);
    assert!(block_specs.iter().all(|s| {
        s.package_sid.as_deref() == Some(sid_a)
            && s.weight == WFP_WEIGHT_BLOCK_PACKAGE
            && s.action == WfpFilterAction::Block
    }));

    // Scoped package-wide Permit builds IPv4+IPv6 specs carrying `package_sid` and weight 12
    // (beats app-wide TransientContainment / Preemptive Block weight 11).
    let permit_specs = build_wfp_scoped_filter_specs(bth, Some(sid_a), None, true)
        .expect("build scoped package-wide permit specs");
    assert_eq!(permit_specs.len(), 2);
    assert!(permit_specs.iter().all(|s| {
        s.package_sid.as_deref() == Some(sid_a)
            && s.weight == WFP_WEIGHT_PERMIT_PACKAGE
            && s.action == WfpFilterAction::Permit
    }));

    // Scoped remote-IP Permit builds single-stack spec with weight 13.
    let ip_permit_specs = build_wfp_scoped_filter_specs(
        bth,
        Some(sid_a),
        Some(IpAddr::V4(Ipv4Addr::new(20, 42, 65, 88))),
        true,
    )
    .expect("build scoped IP permit spec");
    assert_eq!(ip_permit_specs.len(), 1);
    assert_eq!(ip_permit_specs[0].package_sid.as_deref(), Some(sid_a));
    assert_eq!(ip_permit_specs[0].weight, WFP_WEIGHT_PERMIT_SPECIFIC);

    // Invalid / non-AppContainer SIDs and protected binaries must be rejected fail-closed.
    assert!(build_wfp_scoped_filter_specs(bth, Some("S-1-5-18"), None, true).is_err());
    assert!(build_wfp_scoped_filter_specs(bth, Some(""), None, false).is_err());
    assert!(
        build_wfp_scoped_filter_specs(
            Path::new(r"C:\Windows\System32\svchost.exe"),
            Some(sid_a),
            None,
            false
        )
        .is_err()
    );

    // Engine transaction rollback on second filter failure leaves 0 committed filters.
    let (backend, state) = MockWfpBackend::new_dynamic();
    state.lock().unwrap().fail_on_layer = Some(WfpLayer::AleAuthConnectV6);
    let engine = WfpDynamicEngine::from_backend(Box::new(backend)).expect("create mock engine");
    assert!(
        engine
            .add_scoped_app_rule(bth, Some(sid_a), None, false)
            .is_err(),
        "second filter failure must abort transaction"
    );
    assert_eq!(engine.active_handle_count(), 0);
    assert!(state.lock().unwrap().committed_filters.is_empty());

    // Success transaction commits both IPv4 + IPv6 scoped filters under one handle.
    state.lock().unwrap().fail_on_layer = None;
    let ctrl = crate::WindowsDefenseController::with_wfp_engine(engine);
    let handle = ctrl
        .add_wfp_scoped_app_rule(bth, Some(sid_a), None, true)
        .expect("WindowsDefenseController scoped add succeeds");
    assert_ne!(handle, 0);
    assert_eq!(state.lock().unwrap().committed_filters.len(), 2);
    ctrl.remove_wfp_rule(handle)
        .expect("remove scoped rule handle");
    assert!(state.lock().unwrap().committed_filters.is_empty());
}
