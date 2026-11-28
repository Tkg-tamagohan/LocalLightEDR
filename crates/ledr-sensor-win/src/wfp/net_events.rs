//! WFP net-event drop parsing, BFE callback, and subscription lifetime management (`BUG_0001`).

use std::collections::HashMap;
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_NET_EVENT2, FWPM_NET_EVENT_CLASSIFY_DROP2, FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET,
    FWPM_NET_EVENT_FLAG_PACKAGE_ID_SET, FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET,
    FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET, FWPM_NET_EVENT_HEADER2, FWPM_NET_EVENT_TYPE,
    FWPM_NET_EVENT_TYPE_CLASSIFY_DROP, FWP_IP_VERSION_V4, FWP_IP_VERSION_V6,
};

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
    pub package_sid: Option<String>,
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
    let package_sid = if (header.flags & FWPM_NET_EVENT_FLAG_PACKAGE_ID_SET) != 0
        && !header.packageSid.is_null()
    {
        crate::etw::tdh::sid_ptr_to_string(header.packageSid.cast::<c_void>())
            .ok()
            .and_then(|sid| {
                let trimmed = sid.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_owned())
            })
    } else {
        None
    };

    Some(WfpDropEvent {
        os_filter_id: drop_info.filterId,
        rule_handle: meta.rule_handle,
        exe_path: meta.exe_path.clone(),
        protocol,
        dst_ip,
        dst_port,
        timestamp_ms,
        package_sid,
    })
}

pub(super) struct NetEventCallbackContext {
    pub(super) active: AtomicBool,
    pub(super) filter_index: Arc<RwLock<HashMap<u64, WfpFilterMeta>>>,
    pub(super) sink: WfpDropSinkFn,
}

pub(super) struct NetEventSubscription {
    pub(super) events_handle: HANDLE,
    pub(super) ctx_ptr: *mut NetEventCallbackContext,
}

#[derive(Default)]
pub(super) struct NetEventSubscriptionState {
    pub(super) sub: Option<NetEventSubscription>,
    pub(super) enabled_net_events_by_us: bool,
}

impl NetEventSubscriptionState {
    pub(super) fn unsubscribe_with<F, G>(
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

pub(super) unsafe extern "system" fn wfp_net_event_callback(
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
