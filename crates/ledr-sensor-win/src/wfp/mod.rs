//! Windows Filtering Platform (WFP) dynamic SubLayer and outbound rule engine (`L-03`, `AUTO-04`).
//!
//! Uses `FWPM_SESSION_FLAG_DYNAMIC` with a dedicated LocalEDR provider and SubLayer so that
//! closing the engine handle or an unexpected daemon termination automatically purges all
//! dynamic outbound filters from the Windows Base Filtering Engine (BFE) without leaving
//! permanent network lockouts.

use std::collections::HashMap;
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use ledr_proto::is_never_suspend_process;
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_ACTION0, FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_DISPLAY_DATA0,
    FWPM_ENGINE_COLLECT_NET_EVENTS, FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_NONE,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_NET_EVENT2,
    FWPM_NET_EVENT_CLASSIFY_DROP2, FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET,
    FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET, FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET,
    FWPM_NET_EVENT_HEADER2, FWPM_NET_EVENT_SUBSCRIPTION0, FWPM_NET_EVENT_TYPE,
    FWPM_NET_EVENT_TYPE_CLASSIFY_DROP, FWPM_PROVIDER0, FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC,
    FWPM_SUBLAYER0, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_ARRAY16, FWP_BYTE_ARRAY16_TYPE,
    FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0,
    FWP_IP_VERSION_V4, FWP_IP_VERSION_V6, FWP_MATCH_EQUAL, FWP_UINT32, FWP_UINT8,
    FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK, FWP_VALUE0,
    FWP_VALUE0_0, FwpmEngineClose0, FwpmEngineGetOption0, FwpmEngineOpen0, FwpmEngineSetOption0,
    FwpmFilterAdd0, FwpmFilterDeleteById0, FwpmFreeMemory0, FwpmGetAppIdFromFileName0,
    FwpmNetEventSubscribe1, FwpmNetEventUnsubscribe0, FwpmProviderAdd0, FwpmProviderDeleteByKey0,
    FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0, FwpmTransactionAbort0, FwpmTransactionBegin0,
    FwpmTransactionCommit0,
};
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

/// Dedicated WFP provider GUID owned by LocalEDR.
pub const LEDR_WFP_PROVIDER_GUID: GUID = GUID::from_u128(0x8d5b3a72_4c1e_4f9b_9a23_7e61b50c3d11);

/// Dedicated WFP SubLayer GUID owned by LocalEDR (`AUTO-04`).
pub const LEDR_WFP_SUBLAYER_GUID: GUID = GUID::from_u128(0x2f4a8e19_7b3c_4d5e_8f12_6c9a0b3e4f22);

/// SubLayer priority weight registered in BFE.
pub const LEDR_WFP_SUBLAYER_WEIGHT: u16 = 0x8000;

/// Filter weight for loopback Permit filters (`127.0.0.0/8` and `::1/128`) — highest priority
/// within LocalEDR's SubLayer so app-wide outbound blocks never break localhost IPC/dev servers
/// (registered without `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT` so other sublayers keep veto rights).
pub const WFP_WEIGHT_LOOPBACK_PERMIT: u8 = 15;

/// Filter weight for an explicit remote-IP Block filter.
pub const WFP_WEIGHT_BLOCK_SPECIFIC: u8 = 14;

/// Filter weight for an explicit remote-IP Permit filter (overrides pre-emptive app-wide block
/// while explicit app-wide `NetworkBlock` rules suppress Permits during daemon reconciliation).
pub const WFP_WEIGHT_PERMIT_SPECIFIC: u8 = 13;

/// Filter weight for an app-wide Block filter (overrides app-wide Permit).
pub const WFP_WEIGHT_BLOCK_APP: u8 = 11;

/// Filter weight for an app-wide Permit filter.
pub const WFP_WEIGHT_PERMIT_APP: u8 = 10;

const ERROR_SUCCESS_U32: u32 = 0;
const FWP_E_FILTER_NOT_FOUND_CODE: u32 = 0x8032_0003;
const FWP_E_ALREADY_EXISTS_CODE: u32 = 0x8032_0009;

/// WFP ALE outbound connect layer targeted by a single OS filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WfpLayer {
    AleAuthConnectV4,
    AleAuthConnectV6,
}

impl WfpLayer {
    /// Returns the Win32 WFP layer GUID for this layer.
    pub const fn layer_guid(self) -> GUID {
        match self {
            Self::AleAuthConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            Self::AleAuthConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        }
    }
}

/// Action applied by a WFP filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WfpFilterAction {
    Block,
    Permit,
}

/// Remote IP condition encoded in WFP native representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WfpRemoteAddress {
    /// IPv4 address stored in host byte order (`FWP_UINT32`).
    V4HostOrder(u32),
    /// IPv6 address stored in network byte order (`FWP_BYTE_ARRAY16_TYPE`).
    V6NetworkOrder([u8; 16]),
}

/// Canonicalizes an [`IpAddr`] for WFP layer routing by unwrapping IPv4-mapped IPv6 addresses
/// (`::ffff:a.b.c.d`) into [`IpAddr::V4`], matching Windows BFE dual-stack ALE classification.
pub fn canonical_wfp_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
    }
}

impl WfpRemoteAddress {
    /// Converts a standard [`IpAddr`] into its WFP condition representation.
    pub fn from_ip(ip: IpAddr) -> Self {
        match canonical_wfp_ip(ip) {
            IpAddr::V4(v4) => Self::V4HostOrder(u32::from(v4)),
            IpAddr::V6(v6) => Self::V6NetworkOrder(v6.octets()),
        }
    }
}

/// Complete, pure specification of a single WFP dynamic filter before Win32 marshaling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WfpFilterSpec {
    pub layer: WfpLayer,
    pub sublayer_guid: GUID,
    pub provider_guid: GUID,
    pub exe_path: String,
    pub remote_addr: Option<WfpRemoteAddress>,
    pub action: WfpFilterAction,
    pub weight: u8,
    pub dynamic_session_required: bool,
}

/// Masked remote-address condition for a SubLayer-wide loopback Permit filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WfpLoopbackCondition {
    /// IPv4 address + netmask in host byte order (`FWP_V4_ADDR_MASK`).
    V4AddrMask { addr: u32, mask: u32 },
    /// IPv6 address in network byte order + prefix length (`FWP_V6_ADDR_MASK`).
    V6AddrMask { addr: [u8; 16], prefix_length: u8 },
}

/// Complete, pure specification of a non-persistent loopback Permit filter registered during
/// dynamic WFP session initialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WfpLoopbackFilterSpec {
    pub layer: WfpLayer,
    pub sublayer_guid: GUID,
    pub provider_guid: GUID,
    pub condition: WfpLoopbackCondition,
    pub action: WfpFilterAction,
    pub weight: u8,
    pub persistent: bool,
    pub clear_action_right: bool,
    pub dynamic_session_required: bool,
}

/// Builds the two non-persistent IPv4 (`127.0.0.0/8`) and IPv6 (`::1/128`) loopback Permit
/// filter specs registered inside LocalEDR's dynamic WFP SubLayer (`L-03`, `AUTO-04`).
pub fn build_loopback_permit_filter_specs() -> [WfpLoopbackFilterSpec; 2] {
    [
        WfpLoopbackFilterSpec {
            layer: WfpLayer::AleAuthConnectV4,
            sublayer_guid: LEDR_WFP_SUBLAYER_GUID,
            provider_guid: LEDR_WFP_PROVIDER_GUID,
            condition: WfpLoopbackCondition::V4AddrMask {
                addr: 0x7F00_0000,
                mask: 0xFF00_0000,
            },
            action: WfpFilterAction::Permit,
            weight: WFP_WEIGHT_LOOPBACK_PERMIT,
            persistent: false,
            clear_action_right: false,
            dynamic_session_required: true,
        },
        WfpLoopbackFilterSpec {
            layer: WfpLayer::AleAuthConnectV6,
            sublayer_guid: LEDR_WFP_SUBLAYER_GUID,
            provider_guid: LEDR_WFP_PROVIDER_GUID,
            condition: WfpLoopbackCondition::V6AddrMask {
                addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                prefix_length: 128,
            },
            action: WfpFilterAction::Permit,
            weight: WFP_WEIGHT_LOOPBACK_PERMIT,
            persistent: false,
            clear_action_right: false,
            dynamic_session_required: true,
        },
    ]
}

/// Computes the deterministic `FWP_UINT8` filter weight (`0..=15`) for `(remote_ip, allow)`.
pub const fn compute_filter_weight(has_remote_ip: bool, allow: bool) -> u8 {
    match (has_remote_ip, allow) {
        (true, false) => WFP_WEIGHT_BLOCK_SPECIFIC,
        (true, true) => WFP_WEIGHT_PERMIT_SPECIFIC,
        (false, false) => WFP_WEIGHT_BLOCK_APP,
        (false, true) => WFP_WEIGHT_PERMIT_APP,
    }
}

/// Normalizes a Windows path for `FwpmGetAppIdFromFileName0` (stripping extended-length `\\?\`
/// prefixes and unifying `/` to `\`).
pub fn normalize_wfp_exe_path(exe_path: &Path) -> String {
    let raw = exe_path.to_string_lossy();
    let trimmed = raw.trim().replace('/', "\\");
    if let Some(rest) = trimmed
        .get(..8)
        .filter(|p| p.eq_ignore_ascii_case(r"\\?\UNC\"))
        .map(|_| format!(r"\\{}", &trimmed[8..]))
    {
        rest
    } else if trimmed
        .get(..4)
        .is_some_and(|p| p.eq_ignore_ascii_case(r"\\?\"))
    {
        trimmed[4..].to_string()
    } else {
        trimmed
    }
}

/// Validates that `exe_path` is safe and eligible for a WFP app-ID filter (`AUTO-02`).
pub fn validate_wfp_rule_request(exe_path: &Path, allow: bool) -> Result<String, String> {
    let normalized = normalize_wfp_exe_path(exe_path);
    if normalized.is_empty() {
        return Err("refusing WFP rule: executable path is empty".to_string());
    }
    if normalized.contains('*') || normalized.contains('?') {
        return Err(format!(
            "refusing WFP rule for wildcard path `{normalized}`: FwpmGetAppIdFromFileName0 requires a concrete file path"
        ));
    }
    let guard_check = normalized.trim_end_matches(['.', ' ']);
    if !allow && (is_never_suspend_process(&normalized) || is_never_suspend_process(guard_check)) {
        return Err(format!(
            "refusing WFP block rule for protected process `{normalized}` (AUTO-02)"
        ));
    }
    Ok(normalized)
}

/// Builds the 1 (single-stack remote IP) or 2 (dual-stack app-wide) [`WfpFilterSpec`] items
/// registered atomically under one opaque `u64` rule handle.
pub fn build_wfp_filter_specs(
    exe_path: &Path,
    remote_ip: Option<IpAddr>,
    allow: bool,
) -> Result<Vec<WfpFilterSpec>, String> {
    let normalized = validate_wfp_rule_request(exe_path, allow)?;
    let action = if allow {
        WfpFilterAction::Permit
    } else {
        WfpFilterAction::Block
    };
    let canonical_remote = remote_ip.map(canonical_wfp_ip);
    let weight = compute_filter_weight(canonical_remote.is_some(), allow);

    let specs = match canonical_remote {
        Some(IpAddr::V4(v4)) => vec![WfpFilterSpec {
            layer: WfpLayer::AleAuthConnectV4,
            sublayer_guid: LEDR_WFP_SUBLAYER_GUID,
            provider_guid: LEDR_WFP_PROVIDER_GUID,
            exe_path: normalized,
            remote_addr: Some(WfpRemoteAddress::from_ip(IpAddr::V4(v4))),
            action,
            weight,
            dynamic_session_required: true,
        }],
        Some(IpAddr::V6(v6)) => vec![WfpFilterSpec {
            layer: WfpLayer::AleAuthConnectV6,
            sublayer_guid: LEDR_WFP_SUBLAYER_GUID,
            provider_guid: LEDR_WFP_PROVIDER_GUID,
            exe_path: normalized,
            remote_addr: Some(WfpRemoteAddress::from_ip(IpAddr::V6(v6))),
            action,
            weight,
            dynamic_session_required: true,
        }],
        None => vec![
            WfpFilterSpec {
                layer: WfpLayer::AleAuthConnectV4,
                sublayer_guid: LEDR_WFP_SUBLAYER_GUID,
                provider_guid: LEDR_WFP_PROVIDER_GUID,
                exe_path: normalized.clone(),
                remote_addr: None,
                action,
                weight,
                dynamic_session_required: true,
            },
            WfpFilterSpec {
                layer: WfpLayer::AleAuthConnectV6,
                sublayer_guid: LEDR_WFP_SUBLAYER_GUID,
                provider_guid: LEDR_WFP_PROVIDER_GUID,
                exe_path: normalized,
                remote_addr: None,
                action,
                weight,
                dynamic_session_required: true,
            },
        ],
    };

    Ok(specs)
}

/// Metadata indexed per OS WFP filter ID so BFE net-event drop callbacks can map dropped
/// connections back to the owning rule handle and executable without acquiring engine locks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WfpFilterMeta {
    pub rule_handle: u64,
    pub exe_path: String,
    pub allow: bool,
}

/// Outbound connection drop captured from WFP net-event subscriptions for pre-emptively or
/// policy-blocked executables (`BUG_0001`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WfpDropEvent {
    pub os_filter_id: u64,
    pub rule_handle: u64,
    pub exe_path: String,
    pub protocol: u8,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub timestamp_ms: i64,
}

/// Callback sink invoked when a LocalEDR-managed WFP block filter drops an outbound connection.
pub type WfpDropSinkFn = Arc<dyn Fn(WfpDropEvent) + Send + Sync>;

/// Pure parser converting Win32 `FWPM_NET_EVENT2` classify-drop header and drop payload fields
/// into a [`WfpDropEvent`] when the event represents a non-loopback drop on an active
/// LocalEDR block (`!meta.allow`) filter.
pub fn parse_wfp_classify_drop_fields(
    event_type: FWPM_NET_EVENT_TYPE,
    header: &FWPM_NET_EVENT_HEADER2,
    classify_drop: Option<&FWPM_NET_EVENT_CLASSIFY_DROP2>,
    filter_index: &HashMap<u64, WfpFilterMeta>,
) -> Option<WfpDropEvent> {
    if event_type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP {
        return None;
    }
    let drop_info = classify_drop?;
    if drop_info.isLoopback.as_bool() {
        return None;
    }
    let meta = filter_index.get(&drop_info.filterId)?;
    if meta.allow {
        return None;
    }
    if (header.flags & FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET) == 0 {
        return None;
    }

    let dst_ip = match header.ipVersion {
        FWP_IP_VERSION_V4 => {
            // SAFETY: `header.ipVersion == FWP_IP_VERSION_V4` selects `remoteAddrV4` (host order).
            let v4_host = unsafe { header.Anonymous2.remoteAddrV4 };
            IpAddr::V4(Ipv4Addr::from(v4_host))
        }
        FWP_IP_VERSION_V6 => {
            // SAFETY: `header.ipVersion == FWP_IP_VERSION_V6` selects `remoteAddrV6` (network order).
            let v6_bytes = unsafe { header.Anonymous2.remoteAddrV6.byteArray16 };
            IpAddr::V6(Ipv6Addr::from(v6_bytes))
        }
        _ => return None,
    };

    let protocol = if (header.flags & FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET) != 0 {
        header.ipProtocol
    } else {
        0
    };
    let dst_port = if (header.flags & FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET) != 0 {
        header.remotePort
    } else {
        0
    };

    let ft_100ns = crate::etw::tdh::filetime_to_u64(header.timeStamp);
    let timestamp_ms = crate::etw::tdh::filetime_100ns_to_unix_ms(ft_100ns);

    Some(WfpDropEvent {
        os_filter_id: drop_info.filterId,
        rule_handle: meta.rule_handle,
        exe_path: meta.exe_path.clone(),
        protocol,
        dst_ip,
        dst_port,
        timestamp_ms,
    })
}

/// Low-level WFP operations boundary allowing unit tests to verify dual-stack transaction
/// atomicity, rollback, handle bookkeeping, and dynamic session invariants without elevation.
pub trait WfpBackend: Send {
    fn begin_transaction(&mut self) -> Result<(), String>;
    fn commit_transaction(&mut self) -> Result<(), String>;
    fn abort_transaction(&mut self);
    fn add_filter(&mut self, spec: &WfpFilterSpec) -> Result<u64, String>;
    fn delete_filter(&mut self, os_filter_id: u64) -> Result<(), String>;
    fn is_dynamic_session(&self) -> bool;
    fn set_drop_sink(
        &mut self,
        _filter_index: Arc<RwLock<HashMap<u64, WfpFilterMeta>>>,
        _sink: Option<WfpDropSinkFn>,
    ) -> Result<(), String> {
        Ok(())
    }
}

struct OwnedFwpByteBlob(*mut FWP_BYTE_BLOB);

impl OwnedFwpByteBlob {
    fn from_exe_path(exe_path: &str) -> Result<Self, String> {
        let wide: Vec<u16> = exe_path.encode_utf16().chain(std::iter::once(0)).collect();
        let mut blob_ptr: *mut FWP_BYTE_BLOB = ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated UTF-16 and `blob_ptr` receives a BFE-allocated blob
        // freed via `FwpmFreeMemory0` on `Drop`.
        let status = unsafe { FwpmGetAppIdFromFileName0(PCWSTR(wide.as_ptr()), &mut blob_ptr) };
        if status != ERROR_SUCCESS_U32 || blob_ptr.is_null() {
            return Err(format!(
                "FwpmGetAppIdFromFileName0(`{exe_path}`) failed: 0x{status:08X}"
            ));
        }
        Ok(Self(blob_ptr))
    }

    fn as_mut_ptr(&self) -> *mut FWP_BYTE_BLOB {
        self.0
    }
}

impl Drop for OwnedFwpByteBlob {
    fn drop(&mut self) {
        if !self.0.is_null() {
            let mut raw = self.0.cast::<c_void>();
            // SAFETY: `self.0` was allocated by `FwpmGetAppIdFromFileName0` and is freed once.
            unsafe { FwpmFreeMemory0(&mut raw) };
            self.0 = ptr::null_mut();
        }
    }
}

struct OwnedWfpEngineHandle(HANDLE);

// SAFETY: A WFP engine handle from `FwpmEngineOpen0` is an opaque RPC/BFE session handle that is
// safe to move across threads when synchronized by `Mutex` inside `WfpDynamicEngine`.
unsafe impl Send for OwnedWfpEngineHandle {}

impl OwnedWfpEngineHandle {
    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedWfpEngineHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() && !self.0.0.is_null() {
            // SAFETY: `self.0` was opened by `FwpmEngineOpen0` and is closed once here, which
            // automatically removes all dynamic filters owned by this session (`AUTO-04`).
            let status = unsafe { FwpmEngineClose0(self.0) };
            if status != ERROR_SUCCESS_U32 {
                tracing::debug!(status = format_args!("0x{status:08X}"), "FwpmEngineClose0 returned non-zero");
            }
            self.0 = HANDLE::default();
        }
    }
}

struct NetEventCallbackContext {
    active: AtomicBool,
    filter_index: Arc<RwLock<HashMap<u64, WfpFilterMeta>>>,
    sink: WfpDropSinkFn,
}

struct NetEventSubscription {
    events_handle: HANDLE,
    ctx_ptr: *mut NetEventCallbackContext,
}

#[derive(Default)]
struct NetEventSubscriptionState {
    sub: Option<NetEventSubscription>,
    enabled_net_events_by_us: bool,
}

impl NetEventSubscriptionState {
    fn unsubscribe_with<F, G>(
        &mut self,
        unsubscribe_fn: F,
        disable_collect_fn: G,
    ) -> Result<(), String>
    where
        F: FnOnce(HANDLE) -> Result<(), u32>,
        G: FnOnce() -> Result<(), u32>,
    {
        let mut first_err: Option<String> = None;

        // CRITICAL ordering: deactivate sink dispatch first, call `FwpmNetEventUnsubscribe0`,
        // and ONLY free `ctx_ptr` (`Box::from_raw`) if unsubscribe succeeded. If unsubscribe fails,
        // BFE may still invoke the callback, so keep `sub` (without freeing `ctx_ptr`).
        if let Some(sub) = self.sub.take() {
            // SAFETY: `sub.ctx_ptr` stays valid while owned by `self.sub`.
            unsafe {
                (*sub.ctx_ptr).active.store(false, Ordering::Release);
            }
            match unsubscribe_fn(sub.events_handle) {
                Ok(()) => {
                    // SAFETY: `FwpmNetEventUnsubscribe0` succeeded and waited for in-flight
                    // callbacks to complete; `sub.ctx_ptr` was allocated via `Box::into_raw`.
                    unsafe { drop(Box::from_raw(sub.ctx_ptr)) };
                }
                Err(status) => {
                    self.sub = Some(sub);
                    first_err = Some(format!("FwpmNetEventUnsubscribe0 failed: 0x{status:08X}"));
                }
            }
        }

        if self.enabled_net_events_by_us && self.sub.is_none() {
            match disable_collect_fn() {
                Ok(()) => {
                    self.enabled_net_events_by_us = false;
                }
                Err(status) => {
                    if first_err.is_none() {
                        first_err = Some(format!(
                            "FwpmEngineSetOption0(FWPM_ENGINE_COLLECT_NET_EVENTS=0) failed: 0x{status:08X}"
                        ));
                    }
                }
            }
        }

        match first_err {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }
}

// SAFETY: `events_handle` is a BFE net-event subscription handle from `FwpmNetEventSubscribe1`
// and `ctx_ptr` points to a heap-allocated `NetEventCallbackContext` containing `Send + Sync`
// fields. `LiveWfpBackend` is synchronized by `Mutex` in `WfpDynamicEngine` and unsubscribes
// via `FwpmNetEventUnsubscribe0` before freeing `ctx_ptr`.
unsafe impl Send for NetEventSubscription {}

unsafe extern "system" fn wfp_net_event_callback(
    context: *mut c_void,
    event: *const FWPM_NET_EVENT2,
) {
    if context.is_null() || event.is_null() {
        return;
    }
    // SAFETY: `context` points to a live `NetEventCallbackContext` kept alive until
    // `FwpmNetEventUnsubscribe0` returns `ERROR_SUCCESS`.
    let ctx = unsafe { &*(context as *const NetEventCallbackContext) };
    if !ctx.active.load(Ordering::Acquire) {
        return;
    }
    // SAFETY: `event` is non-null and valid for the callback duration.
    let ev = unsafe { &*event };
    if ev.r#type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP {
        return;
    }
    // SAFETY: `ev.r#type == FWPM_NET_EVENT_TYPE_CLASSIFY_DROP` selects `classifyDrop`.
    let drop_ptr = unsafe { ev.Anonymous.classifyDrop };
    let classify_drop = if drop_ptr.is_null() {
        None
    } else {
        // SAFETY: BFE guarantees `classifyDrop` is valid when non-null.
        Some(unsafe { &*drop_ptr })
    };

    let parsed = {
        let index = ctx.filter_index.read().unwrap_or_else(|e| e.into_inner());
        parse_wfp_classify_drop_fields(ev.r#type, &ev.header, classify_drop, &index)
    };
    if let Some(drop_event) = parsed {
        if ctx.active.load(Ordering::Acquire) {
            (ctx.sink)(drop_event);
        }
    }
}

/// Live Windows Filtering Platform backend backed by `fwpuclnt.dll` with
/// `FWPM_SESSION_FLAG_DYNAMIC` and LocalEDR's dedicated SubLayer (`L-03`, `AUTO-04`).
pub struct LiveWfpBackend {
    engine: OwnedWfpEngineHandle,
    loopback_filter_ids: Vec<u64>,
    net_event_state: NetEventSubscriptionState,
}

impl LiveWfpBackend {
    /// Opens a dynamic WFP session (`FWPM_SESSION_FLAG_DYNAMIC`) and ensures LocalEDR's custom
    /// provider, SubLayer, and IPv4/IPv6 loopback Permit filters are registered atomically.
    pub fn open_dynamic() -> Result<Self, String> {
        let mut session_name = encode_wide_nul("LocalEDR Dynamic Firewall Session");
        let mut session_desc =
            encode_wide_nul("Dynamic outbound firewall session auto-cleaned on daemon exit");
        let session = FWPM_SESSION0 {
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(session_name.as_mut_ptr()),
                description: PWSTR(session_desc.as_mut_ptr()),
            },
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            ..Default::default()
        };

        let mut raw_handle = HANDLE::default();
        // SAFETY: `session` and its display strings stay live across `FwpmEngineOpen0`.
        let status = unsafe {
            FwpmEngineOpen0(
                PCWSTR::null(),
                RPC_C_AUTHN_WINNT,
                None,
                Some(&session),
                &mut raw_handle,
            )
        };
        if status != ERROR_SUCCESS_U32 || raw_handle.is_invalid() || raw_handle.0.is_null() {
            return Err(format!(
                "FwpmEngineOpen0(FWPM_SESSION_FLAG_DYNAMIC) failed: 0x{status:08X}"
            ));
        }

        let engine = OwnedWfpEngineHandle(raw_handle);
        let loopback_filter_ids = register_provider_and_sublayer(engine.raw())?;

        tracing::info!(
            sublayer = ?LEDR_WFP_SUBLAYER_GUID,
            loopback_filters = loopback_filter_ids.len(),
            "initialized WFP dynamic session, LocalEDR SubLayer, and loopback Permit filters"
        );
        Ok(Self {
            engine,
            loopback_filter_ids,
            net_event_state: NetEventSubscriptionState::default(),
        })
    }

    fn unsubscribe_net_events(&mut self) -> Result<(), String> {
        let engine_raw = self.engine.raw();
        self.net_event_state.unsubscribe_with(
            |events_handle| {
                // SAFETY: `engine_raw` and `events_handle` are valid WFP handles.
                let status = unsafe { FwpmNetEventUnsubscribe0(engine_raw, events_handle) };
                if status == ERROR_SUCCESS_U32 {
                    Ok(())
                } else {
                    Err(status)
                }
            },
            || {
                let disable_val = FWP_VALUE0 {
                    r#type: FWP_UINT32,
                    Anonymous: FWP_VALUE0_0 { uint32: 0 },
                };
                // SAFETY: `engine_raw` is open and `disable_val` stays live across the call.
                let status = unsafe {
                    FwpmEngineSetOption0(
                        engine_raw,
                        FWPM_ENGINE_COLLECT_NET_EVENTS,
                        &disable_val,
                    )
                };
                if status == ERROR_SUCCESS_U32 {
                    Ok(())
                } else {
                    Err(status)
                }
            },
        )
    }
}

impl Drop for LiveWfpBackend {
    fn drop(&mut self) {
        // CRITICAL lifetime/drop order:
        // 1. `FwpmNetEventUnsubscribe0` + wait for return -> free `ctx_ptr` -> restore option.
        // 2. Delete dynamic loopback filters, SubLayer, and Provider.
        // 3. `OwnedWfpEngineHandle::drop` calls `FwpmEngineClose0` (`AUTO-04`).
        if let Err(err) = self.unsubscribe_net_events() {
            tracing::debug!(error = %err, "LiveWfpBackend net-event cleanup warning on drop");
        }

        let handle = self.engine.raw();
        if !handle.is_invalid() && !handle.0.is_null() {
            // SAFETY: `handle` is an open WFP engine handle and GUIDs/filter IDs are valid.
            unsafe {
                for filter_id in self.loopback_filter_ids.drain(..) {
                    let _ = FwpmFilterDeleteById0(handle, filter_id);
                }
                let _ = FwpmSubLayerDeleteByKey0(handle, &LEDR_WFP_SUBLAYER_GUID);
                let _ = FwpmProviderDeleteByKey0(handle, &LEDR_WFP_PROVIDER_GUID);
            }
        }
    }
}

fn register_provider_and_sublayer(engine: HANDLE) -> Result<Vec<u64>, String> {
    // SAFETY: `engine` is an open WFP session handle.
    let begin_status = unsafe { FwpmTransactionBegin0(engine, 0) };
    if begin_status != ERROR_SUCCESS_U32 {
        return Err(format!(
            "FwpmTransactionBegin0 failed while registering SubLayer: 0x{begin_status:08X}"
        ));
    }

    let setup_res = (|| -> Result<Vec<u64>, String> {
        let mut prov_name = encode_wide_nul("LocalEDR");
        let mut prov_desc = encode_wide_nul("LocalEDR Dynamic Outbound Firewall Provider");
        let provider = FWPM_PROVIDER0 {
            providerKey: LEDR_WFP_PROVIDER_GUID,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(prov_name.as_mut_ptr()),
                description: PWSTR(prov_desc.as_mut_ptr()),
            },
            flags: 0, // Never persistent
            ..Default::default()
        };
        // SAFETY: `provider` and its UTF-16 display strings remain live for `FwpmProviderAdd0`.
        let prov_status = unsafe { FwpmProviderAdd0(engine, &provider, None) };
        if prov_status != ERROR_SUCCESS_U32 && prov_status != FWP_E_ALREADY_EXISTS_CODE {
            return Err(format!("FwpmProviderAdd0 failed: 0x{prov_status:08X}"));
        }

        let mut sl_name = encode_wide_nul("LocalEDR Outbound SubLayer");
        let mut sl_desc = encode_wide_nul("Dynamic outbound application filter sublayer");
        let mut provider_guid = LEDR_WFP_PROVIDER_GUID;
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: LEDR_WFP_SUBLAYER_GUID,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(sl_name.as_mut_ptr()),
                description: PWSTR(sl_desc.as_mut_ptr()),
            },
            flags: 0, // Never persistent
            providerKey: &mut provider_guid,
            weight: LEDR_WFP_SUBLAYER_WEIGHT,
            ..Default::default()
        };
        // SAFETY: `sublayer`, `provider_guid`, and display strings stay live for `FwpmSubLayerAdd0`.
        let sl_status = unsafe { FwpmSubLayerAdd0(engine, &sublayer, None) };
        if sl_status != ERROR_SUCCESS_U32 && sl_status != FWP_E_ALREADY_EXISTS_CODE {
            return Err(format!("FwpmSubLayerAdd0 failed: 0x{sl_status:08X}"));
        }

        let loopback_specs = build_loopback_permit_filter_specs();
        let mut loopback_ids = Vec::with_capacity(loopback_specs.len());
        for spec in &loopback_specs {
            let filter_id = add_loopback_permit_filter(engine, spec)?;
            loopback_ids.push(filter_id);
        }
        Ok(loopback_ids)
    })();

    let loopback_ids = match setup_res {
        Ok(ids) => ids,
        Err(err) => {
            // SAFETY: Aborts the active WFP write transaction on setup failure.
            unsafe {
                let _ = FwpmTransactionAbort0(engine);
            }
            return Err(err);
        }
    };

    // SAFETY: Commits the active WFP write transaction.
    let commit_status = unsafe { FwpmTransactionCommit0(engine) };
    if commit_status != ERROR_SUCCESS_U32 {
        unsafe {
            let _ = FwpmTransactionAbort0(engine);
        }
        return Err(format!(
            "FwpmTransactionCommit0 failed while registering SubLayer: 0x{commit_status:08X}"
        ));
    }

    Ok(loopback_ids)
}

fn add_loopback_permit_filter(
    engine: HANDLE,
    spec: &WfpLoopbackFilterSpec,
) -> Result<u64, String> {
    let mut v4_mask_storage = match spec.condition {
        WfpLoopbackCondition::V4AddrMask { addr, mask } => {
            Some(FWP_V4_ADDR_AND_MASK { addr, mask })
        }
        WfpLoopbackCondition::V6AddrMask { .. } => None,
    };
    let mut v6_mask_storage = match spec.condition {
        WfpLoopbackCondition::V6AddrMask {
            addr,
            prefix_length,
        } => Some(FWP_V6_ADDR_AND_MASK {
            addr,
            prefixLength: prefix_length,
        }),
        WfpLoopbackCondition::V4AddrMask { .. } => None,
    };

    let condition_value = match spec.condition {
        WfpLoopbackCondition::V4AddrMask { .. } => FWP_CONDITION_VALUE0 {
            r#type: FWP_V4_ADDR_MASK,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                v4AddrMask: v4_mask_storage
                    .as_mut()
                    .map_or(ptr::null_mut(), |v| v as *mut FWP_V4_ADDR_AND_MASK),
            },
        },
        WfpLoopbackCondition::V6AddrMask { .. } => FWP_CONDITION_VALUE0 {
            r#type: FWP_V6_ADDR_MASK,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                v6AddrMask: v6_mask_storage
                    .as_mut()
                    .map_or(ptr::null_mut(), |v| v as *mut FWP_V6_ADDR_AND_MASK),
            },
        },
    };

    let mut condition = FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: condition_value,
    };

    let layer_label = match spec.layer {
        WfpLayer::AleAuthConnectV4 => "v4",
        WfpLayer::AleAuthConnectV6 => "v6",
    };
    let mut filter_name = encode_wide_nul(&format!(
        "LocalEDR Loopback Permit ({layer_label})"
    ));
    let mut filter_desc =
        encode_wide_nul("Dynamic loopback permit within LocalEDR SubLayer");
    let mut provider_guid = spec.provider_guid;

    debug_assert!(!spec.persistent && !spec.clear_action_right);
    let filter = FWPM_FILTER0 {
        displayData: FWPM_DISPLAY_DATA0 {
            name: PWSTR(filter_name.as_mut_ptr()),
            description: PWSTR(filter_desc.as_mut_ptr()),
        },
        // Dynamic via session flag; never persistent and never CLEAR_ACTION_RIGHT.
        flags: FWPM_FILTER_FLAG_NONE,
        providerKey: &mut provider_guid,
        layerKey: spec.layer.layer_guid(),
        subLayerKey: spec.sublayer_guid,
        weight: FWP_VALUE0 {
            r#type: FWP_UINT8,
            Anonymous: FWP_VALUE0_0 { uint8: spec.weight },
        },
        numFilterConditions: 1,
        filterCondition: &mut condition,
        action: FWPM_ACTION0 {
            r#type: match spec.action {
                WfpFilterAction::Permit => FWP_ACTION_PERMIT,
                WfpFilterAction::Block => FWP_ACTION_BLOCK,
            },
            ..Default::default()
        },
        ..Default::default()
    };

    let mut filter_id: u64 = 0;
    // SAFETY: `filter`, `condition`, `v4_mask_storage`, `v6_mask_storage`, `provider_guid`,
    // and UTF-16 display strings remain valid for the entire `FwpmFilterAdd0` call.
    let status = unsafe { FwpmFilterAdd0(engine, &filter, None, Some(&mut filter_id)) };
    if status != ERROR_SUCCESS_U32 {
        return Err(format!(
            "FwpmFilterAdd0(Loopback Permit, {layer_label}) failed: 0x{status:08X}"
        ));
    }
    Ok(filter_id)
}

impl WfpBackend for LiveWfpBackend {
    fn begin_transaction(&mut self) -> Result<(), String> {
        // SAFETY: `self.engine.raw()` is a live WFP engine handle.
        let status = unsafe { FwpmTransactionBegin0(self.engine.raw(), 0) };
        if status != ERROR_SUCCESS_U32 {
            return Err(format!("FwpmTransactionBegin0 failed: 0x{status:08X}"));
        }
        Ok(())
    }

    fn commit_transaction(&mut self) -> Result<(), String> {
        // SAFETY: `self.engine.raw()` has an open WFP transaction.
        let status = unsafe { FwpmTransactionCommit0(self.engine.raw()) };
        if status != ERROR_SUCCESS_U32 {
            return Err(format!("FwpmTransactionCommit0 failed: 0x{status:08X}"));
        }
        Ok(())
    }

    fn abort_transaction(&mut self) {
        // SAFETY: Aborts the active WFP transaction on error.
        let status = unsafe { FwpmTransactionAbort0(self.engine.raw()) };
        if status != ERROR_SUCCESS_U32 {
            tracing::debug!(
                status = format_args!("0x{status:08X}"),
                "FwpmTransactionAbort0 returned non-zero"
            );
        }
    }

    fn add_filter(&mut self, spec: &WfpFilterSpec) -> Result<u64, String> {
        let app_blob = OwnedFwpByteBlob::from_exe_path(&spec.exe_path)?;

        let mut v6_addr_storage = match spec.remote_addr {
            Some(WfpRemoteAddress::V6NetworkOrder(bytes)) => {
                Some(FWP_BYTE_ARRAY16 { byteArray16: bytes })
            }
            _ => None,
        };

        let mut conditions = Vec::with_capacity(2);
        conditions.push(FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_APP_ID,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_BYTE_BLOB_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    byteBlob: app_blob.as_mut_ptr(),
                },
            },
        });

        if let Some(remote) = spec.remote_addr {
            let cond_val = match remote {
                WfpRemoteAddress::V4HostOrder(v4_host) => FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT32,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint32: v4_host },
                },
                WfpRemoteAddress::V6NetworkOrder(_) => {
                    let ptr_v6 = v6_addr_storage
                        .as_mut()
                        .map_or(ptr::null_mut(), |v| v as *mut FWP_BYTE_ARRAY16);
                    FWP_CONDITION_VALUE0 {
                        r#type: FWP_BYTE_ARRAY16_TYPE,
                        Anonymous: FWP_CONDITION_VALUE0_0 {
                            byteArray16: ptr_v6,
                        },
                    }
                }
            };
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: cond_val,
            });
        }

        let action_label = match spec.action {
            WfpFilterAction::Block => "Block",
            WfpFilterAction::Permit => "Permit",
        };
        let layer_label = match spec.layer {
            WfpLayer::AleAuthConnectV4 => "v4",
            WfpLayer::AleAuthConnectV6 => "v6",
        };
        let mut filter_name = encode_wide_nul(&format!(
            "LocalEDR {action_label} ({layer_label}): {}",
            spec.exe_path
        ));
        let mut filter_desc = encode_wide_nul("Dynamic outbound rule managed by LocalEDR");
        let mut provider_guid = spec.provider_guid;

        let filter = FWPM_FILTER0 {
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(filter_name.as_mut_ptr()),
                description: PWSTR(filter_desc.as_mut_ptr()),
            },
            flags: FWPM_FILTER_FLAG_NONE, // Dynamic via session flag; never persistent
            providerKey: &mut provider_guid,
            layerKey: spec.layer.layer_guid(),
            subLayerKey: spec.sublayer_guid,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 { uint8: spec.weight },
            },
            numFilterConditions: u32::try_from(conditions.len()).unwrap_or(0),
            filterCondition: conditions.as_mut_ptr(),
            action: FWPM_ACTION0 {
                r#type: match spec.action {
                    WfpFilterAction::Block => FWP_ACTION_BLOCK,
                    WfpFilterAction::Permit => FWP_ACTION_PERMIT,
                },
                ..Default::default()
            },
            ..Default::default()
        };

        let mut filter_id: u64 = 0;
        // SAFETY: `filter`, `conditions`, `app_blob`, `v6_addr_storage`, `provider_guid`, and
        // UTF-16 display strings remain valid for the entire `FwpmFilterAdd0` call.
        let status = unsafe { FwpmFilterAdd0(self.engine.raw(), &filter, None, Some(&mut filter_id)) };
        if status != ERROR_SUCCESS_U32 {
            return Err(format!(
                "FwpmFilterAdd0({action_label}, {layer_label}, `{}`) failed: 0x{status:08X}",
                spec.exe_path
            ));
        }

        Ok(filter_id)
    }

    fn delete_filter(&mut self, os_filter_id: u64) -> Result<(), String> {
        // SAFETY: `self.engine.raw()` is a live WFP engine handle.
        let status = unsafe { FwpmFilterDeleteById0(self.engine.raw(), os_filter_id) };
        if status != ERROR_SUCCESS_U32 && status != FWP_E_FILTER_NOT_FOUND_CODE {
            return Err(format!(
                "FwpmFilterDeleteById0({os_filter_id}) failed: 0x{status:08X}"
            ));
        }
        Ok(())
    }

    fn is_dynamic_session(&self) -> bool {
        true
    }

    fn set_drop_sink(
        &mut self,
        filter_index: Arc<RwLock<HashMap<u64, WfpFilterMeta>>>,
        sink: Option<WfpDropSinkFn>,
    ) -> Result<(), String> {
        self.unsubscribe_net_events()?;
        let Some(sink) = sink else {
            return Ok(());
        };

        let mut current_opt: *mut FWP_VALUE0 = ptr::null_mut();
        // SAFETY: `self.engine.raw()` is open and `current_opt` receives a BFE-allocated
        // `FWP_VALUE0` freed immediately below via `FwpmFreeMemory0`.
        let get_status = unsafe {
            FwpmEngineGetOption0(
                self.engine.raw(),
                FWPM_ENGINE_COLLECT_NET_EVENTS,
                &mut current_opt,
            )
        };
        if get_status != ERROR_SUCCESS_U32 || current_opt.is_null() {
            return Err(format!(
                "FwpmEngineGetOption0(FWPM_ENGINE_COLLECT_NET_EVENTS) failed: 0x{get_status:08X}"
            ));
        }
        let current_val = unsafe {
            let res = if (*current_opt).r#type == FWP_UINT32 {
                Ok((*current_opt).Anonymous.uint32)
            } else {
                Err(format!(
                    "unexpected FWP_VALUE0 type {} for FWPM_ENGINE_COLLECT_NET_EVENTS",
                    (*current_opt).r#type.0
                ))
            };
            let mut raw = current_opt.cast::<c_void>();
            FwpmFreeMemory0(&mut raw);
            res
        }?;

        if current_val == 0 {
            let enable_val = FWP_VALUE0 {
                r#type: FWP_UINT32,
                Anonymous: FWP_VALUE0_0 { uint32: 1 },
            };
            // SAFETY: `self.engine.raw()` is open and `enable_val` stays live across the call.
            let set_status = unsafe {
                FwpmEngineSetOption0(
                    self.engine.raw(),
                    FWPM_ENGINE_COLLECT_NET_EVENTS,
                    &enable_val,
                )
            };
            if set_status != ERROR_SUCCESS_U32 {
                return Err(format!(
                    "FwpmEngineSetOption0(FWPM_ENGINE_COLLECT_NET_EVENTS=1) failed: 0x{set_status:08X}"
                ));
            }
            self.net_event_state.enabled_net_events_by_us = true;
        }

        let ctx_ptr = Box::into_raw(Box::new(NetEventCallbackContext {
            active: AtomicBool::new(true),
            filter_index,
            sink,
        }));
        let subscription = FWPM_NET_EVENT_SUBSCRIPTION0::default();
        let mut events_handle = HANDLE::default();
        // SAFETY: `self.engine.raw()` is open, `subscription` stays valid across the call,
        // `wfp_net_event_callback` matches `FWPM_NET_EVENT_CALLBACK1`, and `ctx_ptr` remains
        // valid until `FwpmNetEventUnsubscribe0` returns `ERROR_SUCCESS`.
        let sub_status = unsafe {
            FwpmNetEventSubscribe1(
                self.engine.raw(),
                &subscription,
                Some(wfp_net_event_callback),
                Some(ctx_ptr.cast::<c_void>()),
                &mut events_handle,
            )
        };
        if sub_status != ERROR_SUCCESS_U32 || events_handle.is_invalid() || events_handle.0.is_null() {
            // SAFETY: Registration failed so no callback was installed; reclaim `ctx_ptr` now.
            unsafe { drop(Box::from_raw(ctx_ptr)) };
            let _ = self.unsubscribe_net_events();
            return Err(format!("FwpmNetEventSubscribe1 failed: 0x{sub_status:08X}"));
        }

        self.net_event_state.sub = Some(NetEventSubscription {
            events_handle,
            ctx_ptr,
        });
        Ok(())
    }
}

struct WfpEngineState {
    backend: Box<dyn WfpBackend>,
    next_handle: u64,
    handles: HashMap<u64, Vec<u64>>,
}

/// Thread-safe WFP dynamic firewall engine wrapping dual-stack IPv4/IPv6 filter pairs under a
/// single opaque `u64` rule handle (`L-03`, `AUTO-04`).
pub struct WfpDynamicEngine {
    state: Mutex<WfpEngineState>,
    // Separate lock from `state` so BFE net-event callbacks never deadlock against BFE writes.
    filter_index: Arc<RwLock<HashMap<u64, WfpFilterMeta>>>,
}

impl std::fmt::Debug for WfpDynamicEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self
            .state
            .lock()
            .map(|s| s.handles.len())
            .unwrap_or(0);
        f.debug_struct("WfpDynamicEngine")
            .field("active_handles", &count)
            .finish()
    }
}

impl WfpDynamicEngine {
    /// Opens a live Windows WFP dynamic session (`FWPM_SESSION_FLAG_DYNAMIC`) and registers
    /// LocalEDR's dedicated SubLayer.
    pub fn open_dynamic() -> Result<Self, String> {
        let backend = LiveWfpBackend::open_dynamic()?;
        Self::from_backend(Box::new(backend))
    }

    /// Constructs a [`WfpDynamicEngine`] around an injectable [`WfpBackend`] (for tests).
    pub fn from_backend(backend: Box<dyn WfpBackend>) -> Result<Self, String> {
        if !backend.is_dynamic_session() {
            return Err(
                "refusing non-dynamic WFP session: FWPM_SESSION_FLAG_DYNAMIC is mandatory (AUTO-04)"
                    .to_string(),
            );
        }
        Ok(Self {
            state: Mutex::new(WfpEngineState {
                backend,
                next_handle: 1,
                handles: HashMap::new(),
            }),
            filter_index: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Subscribes to WFP net-event drops for active LocalEDR block filters (`BUG_0001`).
    pub fn set_drop_sink(&self, sink: WfpDropSinkFn) -> Result<(), String> {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .backend
            .set_drop_sink(Arc::clone(&self.filter_index), Some(sink))
    }

    /// Unsubscribes any active WFP net-event drop sink.
    pub fn clear_drop_sink(&self) -> Result<(), String> {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .backend
            .set_drop_sink(Arc::clone(&self.filter_index), None)
    }

    /// Atomically adds a dynamic outbound Block or Permit rule for `exe_path` (single-stack when
    /// `remote_ip` is `Some`, dual-stack IPv4+IPv6 inside one WFP transaction when `remote_ip` is
    /// `None`) and returns an opaque non-zero handle `u64`.
    pub fn add_app_rule(
        &self,
        exe_path: &Path,
        remote_ip: Option<IpAddr>,
        allow: bool,
    ) -> Result<u64, String> {
        let specs = build_wfp_filter_specs(exe_path, remote_ip, allow)?;
        let exe_path_norm = specs[0].exe_path.clone();
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());

        guard.backend.begin_transaction()?;
        let mut os_filter_ids = Vec::with_capacity(specs.len());
        for spec in &specs {
            match guard.backend.add_filter(spec) {
                Ok(id) => os_filter_ids.push(id),
                Err(err) => {
                    guard.backend.abort_transaction();
                    return Err(err);
                }
            }
        }
        if let Err(err) = guard.backend.commit_transaction() {
            guard.backend.abort_transaction();
            return Err(err);
        }

        let handle = guard.next_handle;
        guard.next_handle = guard.next_handle.checked_add(1).unwrap_or(1);
        if guard.next_handle == 0 {
            guard.next_handle = 1;
        }
        {
            let mut index = self.filter_index.write().unwrap_or_else(|e| e.into_inner());
            let meta = WfpFilterMeta {
                rule_handle: handle,
                exe_path: exe_path_norm,
                allow,
            };
            for &os_id in &os_filter_ids {
                index.insert(os_id, meta.clone());
            }
        }
        guard.handles.insert(handle, os_filter_ids);
        Ok(handle)
    }

    /// Atomically deletes all OS WFP filters associated with `handle_id`.
    pub fn remove_rule(&self, handle_id: u64) -> Result<(), String> {
        if handle_id == 0 {
            return Err("invalid WFP rule handle 0".to_string());
        }
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let Some(os_ids) = guard.handles.get(&handle_id).cloned() else {
            return Err(format!("unknown WFP rule handle {handle_id}"));
        };

        guard.backend.begin_transaction()?;
        for os_id in &os_ids {
            if let Err(err) = guard.backend.delete_filter(*os_id) {
                guard.backend.abort_transaction();
                return Err(err);
            }
        }
        if let Err(err) = guard.backend.commit_transaction() {
            guard.backend.abort_transaction();
            return Err(err);
        }

        guard.handles.remove(&handle_id);
        {
            let mut index = self.filter_index.write().unwrap_or_else(|e| e.into_inner());
            for os_id in &os_ids {
                index.remove(os_id);
            }
        }
        Ok(())
    }

    /// Returns a snapshot of indexed filter metadata for `os_filter_id` (diagnostics/tests).
    pub fn filter_meta(&self, os_filter_id: u64) -> Option<WfpFilterMeta> {
        self.filter_index
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&os_filter_id)
            .cloned()
    }

    /// Returns the number of currently active opaque rule handles.
    pub fn active_handle_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .handles
            .len()
    }

    /// Returns the OS filter IDs currently mapped to `handle_id` (diagnostics/tests).
    pub fn os_filter_ids_for_handle(&self, handle_id: u64) -> Option<Vec<u64>> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .handles
            .get(&handle_id)
            .cloned()
    }
}

fn encode_wide_nul(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Helper converting an IPv4 address into WFP host-order `u32` (for diagnostics/tests).
pub const fn ipv4_to_wfp_host_order(ip: Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets())
}

/// Helper converting an IPv6 address into WFP network-order bytes (for diagnostics/tests).
pub const fn ipv6_to_wfp_network_order(ip: Ipv6Addr) -> [u8; 16] {
    ip.octets()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

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
}
