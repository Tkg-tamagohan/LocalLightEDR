//! WFP backend trait and live Win32 BFE FFI backend (`L-03`, `AUTO-04`).

use std::collections::HashMap;
use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_ACTION0, FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_ALE_PACKAGE_ID,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_DISPLAY_DATA0, FWPM_ENGINE_COLLECT_NET_EVENTS,
    FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_NONE, FWPM_NET_EVENT_SUBSCRIPTION0,
    FWPM_PROVIDER0, FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0, FWP_ACTION_BLOCK,
    FWP_ACTION_PERMIT, FWP_BYTE_ARRAY16, FWP_BYTE_ARRAY16_TYPE, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE,
    FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_SID, FWP_UINT32, FWP_UINT8,
    FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK, FWP_VALUE0,
    FWP_VALUE0_0, FwpmEngineClose0, FwpmEngineGetOption0, FwpmEngineOpen0, FwpmEngineSetOption0,
    FwpmFilterAdd0, FwpmFilterDeleteById0, FwpmFreeMemory0, FwpmGetAppIdFromFileName0,
    FwpmNetEventSubscribe1, FwpmNetEventUnsubscribe0, FwpmProviderAdd0, FwpmProviderDeleteByKey0,
    FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0, FwpmTransactionAbort0, FwpmTransactionBegin0,
    FwpmTransactionCommit0,
};
use windows::Win32::Security::SID;
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

#[link(name = "advapi32")]
unsafe extern "system" {
    fn ConvertStringSidToSidW(string_sid: *const u16, sid: *mut *mut c_void) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LocalFree(hmem: *mut c_void) -> *mut c_void;
}

use super::net_events::{
    NetEventCallbackContext, NetEventSubscription, NetEventSubscriptionState, WfpDropSinkFn,
    WfpFilterMeta, wfp_net_event_callback,
};
use super::spec::{
    LEDR_WFP_PROVIDER_GUID, LEDR_WFP_SUBLAYER_GUID, LEDR_WFP_SUBLAYER_WEIGHT, WfpFilterAction,
    WfpFilterSpec, WfpLayer, WfpLoopbackCondition, WfpLoopbackFilterSpec, WfpRemoteAddress,
    build_loopback_permit_filter_specs,
};

const ERROR_SUCCESS_U32: u32 = 0;
const FWP_E_FILTER_NOT_FOUND_CODE: u32 = 0x8032_0003;
const FWP_E_ALREADY_EXISTS_CODE: u32 = 0x8032_0009;

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

struct OwnedLocalSid(*mut c_void);

impl OwnedLocalSid {
    fn from_str(sid_str: &str) -> Result<Self, String> {
        let wide = encode_wide_nul(sid_str);
        let mut raw_sid: *mut c_void = ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated UTF-16; `raw_sid` is freed via `LocalFree` on `Drop`.
        let ok = unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut raw_sid) };
        if ok == 0 || raw_sid.is_null() {
            return Err(format!(
                "ConvertStringSidToSidW(`{sid_str}`) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self(raw_sid))
    }

    fn as_sid_ptr(&self) -> *mut SID {
        self.0.cast::<SID>()
    }
}

impl Drop for OwnedLocalSid {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was allocated by `ConvertStringSidToSidW` and is freed once.
            unsafe {
                let _ = LocalFree(self.0);
            }
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
        let package_sid_guard = spec
            .package_sid
            .as_deref()
            .map(OwnedLocalSid::from_str)
            .transpose()?;

        let mut v6_addr_storage = match spec.remote_addr {
            Some(WfpRemoteAddress::V6NetworkOrder(bytes)) => {
                Some(FWP_BYTE_ARRAY16 { byteArray16: bytes })
            }
            _ => None,
        };

        let mut conditions = Vec::with_capacity(3);
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

        if let Some(ref sid_guard) = package_sid_guard {
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_ALE_PACKAGE_ID,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_SID,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        sid: sid_guard.as_sid_ptr(),
                    },
                },
            });
        }

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
        let mut filter_name = match spec.package_sid.as_deref() {
            Some(sid) => encode_wide_nul(&format!(
                "LocalEDR {action_label} ({layer_label}, pkg={sid}): {}",
                spec.exe_path
            )),
            None => encode_wide_nul(&format!(
                "LocalEDR {action_label} ({layer_label}): {}",
                spec.exe_path
            )),
        };
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
        // SAFETY: `filter`, `conditions`, `app_blob`, `package_sid_guard`, `v6_addr_storage`,
        // `provider_guid`, and UTF-16 display strings remain valid for the entire `FwpmFilterAdd0` call.
        let status = unsafe { FwpmFilterAdd0(self.engine.raw(), &filter, None, Some(&mut filter_id)) };
        if status != ERROR_SUCCESS_U32 {
            return Err(format!(
                "FwpmFilterAdd0({action_label}, {layer_label}, pkg={:?}, `{}`) failed: 0x{status:08X}",
                spec.package_sid, spec.exe_path
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

fn encode_wide_nul(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
