//! Kernel-Registry autorun monitoring and KeyObject KCB decision logic.

use std::collections::HashMap;
use std::sync::Mutex;

use ledr_proto::{CanaryCategory, SensorEvent};
use windows::Win32::System::Diagnostics::Etw::EVENT_RECORD;

use super::context::{
    EtwCallbackContext, lookup_registry_key, remember_registry_key, take_registry_key,
};
use super::file_canary::{
    is_autorun_registry_key_u16, is_autorun_registry_value_target,
    is_autorun_registry_value_target_u16,
};
use super::tdh::{TdhEventInfo, filetime_100ns_to_unix_ms};

pub(super) fn handle_kernel_registry(
    record: &EVENT_RECORD,
    event_id: u16,
    ctx: &EtwCallbackContext,
) -> Option<SensorEvent> {
    // CreateKey=1, OpenKey=2, DeleteKey=3, SetValueKey=5, DeleteValueKey=6,
    // CloseKey=13 for `Microsoft-Windows-Kernel-Registry`.
    if !matches!(event_id, 1 | 2 | 3 | 5 | 6 | 13) {
        return None;
    }
    let pid = record.EventHeader.ProcessId;
    if pid == 0 || pid == u32::MAX {
        return None;
    }
    let info = TdhEventInfo::from_record(record)?;
    let facts = registry_event_facts(&info, record, event_id);
    // `ValueName` needs a heap read, so decode it lazily only once the event is
    // confirmed alertable — most SetValueKey traffic is unrelated churn.
    decide_registry_event(&facts, &ctx.registry_kcb_names, || {
        info.get_string("ValueName").filter(|v| !v.is_empty())
    })
}

/// How the key name that arrived with a Kernel-Registry event classifies against the
/// autorun watch-lists. Strings are only materialized for autorun names so unrelated
/// keys stay allocation-free on this hot path (`AUTO-08`).
pub(super) enum RegistryKeyName {
    /// No usable `KeyName`/`BaseName`+`RelativeName` arrived (missing or empty) —
    /// the `KeyObject` cache may still attribute the event.
    Missing,
    /// A name arrived but matches no autorun location: the `KeyObject` is bound to an
    /// unmonitored key, so any cached entry for it is stale and must be evicted.
    Unrelated,
    /// An autorun key whose values are not themselves persistence payloads (e.g.
    /// `Services\*`): key creation/deletion alerts, value writes are filtered below.
    AutorunNonValue(String),
    /// An autorun value target (Run/RunOnce/Winlogon/...): value writes alert.
    AutorunValue(String),
}

/// Decoded fields a Kernel-Registry event needs for the canary decision, kept separate
/// from TDH decoding so the decision path can be driven by unit tests.
pub(super) struct RegistryEventFacts {
    pub(super) pid: u32,
    pub(super) event_id: u16,
    pub(super) key_object: Option<u64>,
    /// NTSTATUS of the operation; `Some(non-zero)` means the operation failed.
    pub(super) status: Option<u32>,
    pub(super) key_name: RegistryKeyName,
    pub(super) disposition: Option<u32>,
    pub(super) access_type: Option<u32>,
    pub(super) timestamp_ms: i64,
}

/// Classifies a raw UTF-16 registry key path for the Kernel-Registry decision path.
/// Returns `None` for absent/empty names so callers can distinguish "no name arrived"
/// (consult the `KeyObject` cache) from "a known unmonitored name arrived" (evict it).
fn classify_registry_key_name(u16_name: &[u16]) -> Option<RegistryKeyName> {
    if u16_name.is_empty() {
        return None;
    }
    if !is_autorun_registry_key_u16(u16_name) {
        return Some(RegistryKeyName::Unrelated);
    }
    Some(if is_autorun_registry_value_target_u16(u16_name) {
        RegistryKeyName::AutorunValue(String::from_utf16_lossy(u16_name))
    } else {
        RegistryKeyName::AutorunNonValue(String::from_utf16_lossy(u16_name))
    })
}

fn registry_event_facts(
    info: &TdhEventInfo,
    record: &EVENT_RECORD,
    event_id: u16,
) -> RegistryEventFacts {
    // CreateKey/OpenKey carry `BaseName` + `RelativeName`; mutating ops carry `KeyName`.
    let key_name = if matches!(event_id, 1 | 2) {
        info.inspect_first_utf16_property(&["KeyName"], classify_registry_key_name)
            .or_else(|| {
                info.inspect_joined_utf16_properties(
                    "BaseName",
                    "RelativeName",
                    classify_registry_key_name,
                )
            })
            .unwrap_or(RegistryKeyName::Missing)
    } else {
        info.inspect_first_utf16_property(&["KeyName"], classify_registry_key_name)
            .unwrap_or(RegistryKeyName::Missing)
    };
    RegistryEventFacts {
        pid: record.EventHeader.ProcessId,
        event_id,
        key_object: info.get_u64("KeyObject"),
        status: info.get_u32("Status"),
        key_name,
        disposition: info.get_u32("Disposition"),
        access_type: info.get_u32("Type"),
        timestamp_ms: filetime_100ns_to_unix_ms(record.EventHeader.TimeStamp.max(0) as u64),
    }
}

pub(super) fn decide_registry_event(
    facts: &RegistryEventFacts,
    key_cache: &Mutex<HashMap<u64, String>>,
    value_name: impl FnOnce() -> Option<String>,
) -> Option<SensorEvent> {
    if !matches!(facts.event_id, 1 | 2 | 3 | 5 | 6 | 13) {
        return None;
    }
    // Registry events carry the operation's NTSTATUS. A failed open/set/delete changed
    // nothing, so it must neither alert nor update the `KeyObject` cache — e.g. a failed
    // DeleteKey leaves the cached name valid and a failed SetValueKey wrote nothing.
    if facts.status.is_some_and(|status| status != 0) {
        return None;
    }
    // CloseKey retires the KeyObject; Windows may recycle the pointer for a different
    // key, so drop its cached name rather than let future empty-name writes inherit a
    // stale attribution. A second handle sharing the same KCB loses attribution here
    // (fail-open miss), which is preferable to a false canary hit on a recycled pointer.
    if facts.event_id == 13 {
        if let Some(key_object) = facts.key_object {
            take_registry_key(key_cache, key_object);
        }
        return None;
    }

    const REG_CREATED_NEW_KEY: u32 = 0x0000_0001;
    // Event 1 (CreateKey) also fires when `RegCreateKeyEx`/`NtCreateKey` merely opens an
    // existing key (`Disposition` = `REG_OPENED_EXISTING_KEY`), and event 2 (OpenKey)
    // covers plain `RegOpenKeyEx`/`NtOpenKey`. Only a genuinely new key under an autorun
    // location is a persistence write, so opens never alert; instead their resolved
    // autorun path is cached under `KeyObject` (which is stable for the opened handle)
    // so that later SetValueKey/DeleteValueKey/DeleteKey events on the same handle —
    // whose `KeyName` arrives empty when the KCB name is not yet populated — can still
    // be attributed.
    let key_name = if matches!(facts.event_id, 1 | 2) {
        if let Some(key_object) = facts.key_object {
            match &facts.key_name {
                // Cache only value-write-relevant autorun keys so the map stays small
                // and is not churned by constant `Services\*` traffic.
                RegistryKeyName::AutorunValue(name) => {
                    remember_registry_key(key_cache, key_object, name);
                }
                // The handle is bound to a known unmonitored key: evict any stale entry
                // so a recycled `KeyObject` cannot inherit an old autorun attribution.
                RegistryKeyName::Unrelated | RegistryKeyName::AutorunNonValue(_) => {
                    take_registry_key(key_cache, key_object);
                }
                RegistryKeyName::Missing => {}
            }
        }
        if facts.event_id == 2
            || facts
                .disposition
                .is_some_and(|disposition| disposition != REG_CREATED_NEW_KEY)
        {
            return None;
        }
        match &facts.key_name {
            RegistryKeyName::AutorunValue(name) | RegistryKeyName::AutorunNonValue(name) => {
                name.clone()
            }
            _ => return None,
        }
    } else {
        match (&facts.key_name, facts.key_object) {
            (RegistryKeyName::AutorunValue(name), Some(key_object)) => {
                if facts.event_id == 3 {
                    take_registry_key(key_cache, key_object);
                } else {
                    remember_registry_key(key_cache, key_object, name);
                }
                name.clone()
            }
            (RegistryKeyName::AutorunNonValue(name), Some(key_object)) => {
                take_registry_key(key_cache, key_object);
                name.clone()
            }
            (RegistryKeyName::Unrelated, Some(key_object)) => {
                take_registry_key(key_cache, key_object);
                return None;
            }
            (RegistryKeyName::Missing, Some(key_object)) => {
                if facts.event_id == 3 {
                    take_registry_key(key_cache, key_object)?
                } else {
                    lookup_registry_key(key_cache, key_object)?
                }
            }
            (RegistryKeyName::AutorunValue(name) | RegistryKeyName::AutorunNonValue(name), None) => {
                name.clone()
            }
            (RegistryKeyName::Unrelated, None) | (RegistryKeyName::Missing, None) => return None,
        }
    };

    // Value writes only matter under the persistence locations where the written value is
    // itself the payload (Run/RunOnce entries, Winlogon shell/userinit). Existing
    // `Services\*` keys see constant benign churn (e.g. `Tcpip\Parameters`), so writes
    // there are not alerted on; service persistence stays covered by new-key creation.
    if matches!(facts.event_id, 5 | 6) && !is_autorun_registry_value_target(&key_name) {
        return None;
    }

    let target_path = if matches!(facts.event_id, 5 | 6) {
        match value_name() {
            Some(value_name) => format!("{key_name}\\{value_name}"),
            None => key_name,
        }
    } else {
        key_name
    };

    let access_mask = facts
        .disposition
        .or(facts.access_type)
        .unwrap_or(facts.event_id as u32);

    Some(SensorEvent::CanaryFileAccess {
        pid: facts.pid,
        target_path,
        category: CanaryCategory::AutorunRegistry,
        access_mask,
        is_write_or_delete: true,
        timestamp_ms: facts.timestamp_ms,
    })
}
