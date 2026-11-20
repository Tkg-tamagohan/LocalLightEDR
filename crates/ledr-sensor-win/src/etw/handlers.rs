//! ETW raw FFI callbacks and per-provider event handlers.

use std::sync::atomic::{AtomicU64, Ordering};

use ledr_proto::{CanaryCategory, ProcessIdentity, ScriptSource, SensorEvent};
use windows::core::GUID;
use windows::Win32::System::Diagnostics::Etw::{EVENT_RECORD, EVENT_TRACE_LOGFILEW};

use super::context::EtwCallbackContext;
use super::registry::handle_kernel_registry;
use super::tdh::{
    TdhEventInfo, filetime_100ns_to_unix_ms, inspect_process_by_pid, parse_dns_query_results,
};

static KERNEL_PROCESS_RECEIVED: AtomicU64 = AtomicU64::new(0);
static KERNEL_PROCESS_TDH_FAILURES: AtomicU64 = AtomicU64::new(0);
static KERNEL_PROCESS_START_EMITTED: AtomicU64 = AtomicU64::new(0);
static KERNEL_PROCESS_STOP_EMITTED: AtomicU64 = AtomicU64::new(0);

#[inline]
fn read_raw_userdata_u32_at_0(record: &EVENT_RECORD) -> Option<u32> {
    if record.UserData.is_null() || record.UserDataLength < 4 {
        return None;
    }
    // SAFETY: `record.UserData` is non-null and has at least 4 readable bytes per `UserDataLength`.
    let bytes = unsafe { std::slice::from_raw_parts(record.UserData.cast::<u8>(), 4) };
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub(super) const WINEVENT_KEYWORD_PROCESS: u64 = 0x10;
pub(super) const KERNEL_FILE_KEYWORDS: u64 = 0x0010 | 0x0020 | 0x0080 | 0x0200 | 0x0400 | 0x0800 | 0x1000;
// Kernel-Registry keyword bits: CloseKey (0x0001) is included so cached KeyObject
// names are invalidated when the handle whose KCB they describe is released.
pub(super) const KERNEL_REGISTRY_KEYWORDS: u64 = 0x0001 | 0x0100 | 0x0200 | 0x1000 | 0x2000 | 0x4000;
/// `Microsoft-Windows-Kernel-Process` (`{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}`).
pub(super) const KERNEL_PROCESS_GUID: GUID = GUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);
/// `Microsoft-Windows-Kernel-File` (`{EDD08927-9CC4-4E65-B970-C2560FB5C289}`).
pub(super) const KERNEL_FILE_GUID: GUID = GUID::from_u128(0xedd08927_9cc4_4e65_b970_c2560fb5c289);
/// `Microsoft-Windows-Kernel-Registry` (`{70EB4F03-C1DE-4F73-A051-33D13D5413BD}`).
pub(super) const KERNEL_REGISTRY_GUID: GUID = GUID::from_u128(0x70eb4f03_c1de_4f73_a051_33d13d5413bd);
/// `Microsoft-Windows-DNS-Client` (`{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}`).
pub(super) const DNS_CLIENT_GUID: GUID = GUID::from_u128(0x1c95126e_7eea_49a9_a3fe_a378b03ddb4d);
/// `Microsoft-Windows-Kernel-Network` (`{7DD42A49-5329-4832-8DFD-43D979153A88}`).
pub(super) const KERNEL_NETWORK_GUID: GUID = GUID::from_u128(0x7dd42a49_5329_4832_8dfd_43d979153a88);
/// `Microsoft-Windows-AMSI` (`{2A576B87-09A7-520E-C21A-4942F0271D67}`).
pub(super) const AMSI_GUID: GUID = GUID::from_u128(0x2a576b87_09a7_520e_c21a_4942f0271d67);
/// `Microsoft-Windows-PowerShell` (`{A0C1853B-5C40-4B15-8766-3CF1C58F985A}`).
pub(super) const POWERSHELL_GUID: GUID = GUID::from_u128(0xa0c1853b_5c40_4b15_8766_3cf1c58f985a);

pub(super) unsafe extern "system" fn buffer_callback(logfile: *mut EVENT_TRACE_LOGFILEW) -> u32 {
    if logfile.is_null() {
        return 0;
    }
    // SAFETY: `logfile` is non-null and provided by ETW runtime.
    let ctx_ptr = unsafe { (*logfile).Context.cast::<EtwCallbackContext>() };
    if ctx_ptr.is_null() {
        return 1;
    }
    // SAFETY: `ctx_ptr` remains valid for the lifetime of `ProcessTrace`.
    let ctx = unsafe { &*ctx_ptr };
    // Return 0 only when cancellation was requested (downstream sink closed or force_abort),
    // allowing graceful stop() to drain all flushed buffers before ProcessTrace exits.
    if ctx.stop_requested.load(Ordering::Acquire) {
        0
    } else {
        1
    }
}

pub(super) unsafe extern "system" fn event_record_callback(event_record: *mut EVENT_RECORD) {
    if event_record.is_null() {
        return;
    }
    // SAFETY: `event_record` is non-null and valid for the callback duration.
    let record = unsafe { &*event_record };
    let ctx_ptr = record.UserContext.cast::<EtwCallbackContext>();
    if ctx_ptr.is_null() {
        return;
    }
    // SAFETY: `ctx_ptr` remains valid until after `ProcessTrace` exits.
    let ctx = unsafe { &*ctx_ptr };
    if ctx.stop_requested.load(Ordering::Acquire) {
        return;
    }

    let provider = record.EventHeader.ProviderId;
    let event_id = record.EventHeader.EventDescriptor.Id;

    let emitted = if provider == KERNEL_PROCESS_GUID {
        let received = KERNEL_PROCESS_RECEIVED.fetch_add(1, Ordering::Relaxed) + 1;
        if received.is_power_of_two() {
            tracing::debug!(
                received,
                event_id,
                version = record.EventHeader.EventDescriptor.Version,
                header_pid = record.EventHeader.ProcessId,
                user_data_len = record.UserDataLength,
                "received Microsoft-Windows-Kernel-Process ETW event"
            );
        }
        match event_id {
            1 => handle_process_start(record, ctx),
            2 => handle_process_stop(record, ctx),
            _ => None,
        }
    } else if provider == KERNEL_FILE_GUID {
        handle_kernel_file(record, event_id, ctx)
    } else if provider == KERNEL_REGISTRY_GUID {
        handle_kernel_registry(record, event_id, ctx)
    } else if provider == DNS_CLIENT_GUID {
        match event_id {
            3008 | 3018 | 3020 | 3006 => handle_dns_client(record, event_id, ctx),
            _ => None,
        }
    } else if provider == KERNEL_NETWORK_GUID {
        match event_id {
            12 | 28 | 42 | 58 => handle_kernel_network(record, event_id, ctx),
            _ => None,
        }
    } else if provider == AMSI_GUID && event_id == 1101 {
        handle_script_event(record, ScriptSource::Amsi, "content")
    } else if provider == POWERSHELL_GUID && event_id == 4104 {
        handle_script_event(record, ScriptSource::PowerShell4104, "ScriptBlockText")
    } else {
        None
    };

    let Some(event) = emitted else {
        return;
    };
    let _ = ctx.dispatch_event(event);
}

fn handle_process_start(record: &EVENT_RECORD, ctx: &EtwCallbackContext) -> Option<SensorEvent> {
    let (pid, parent_pid, mut create_time_100ns, mut exe_path, mut command_line, user_sid) =
        match TdhEventInfo::from_record_with_status(record) {
            Ok(info) => {
                let Some(pid) = info
                    .get_u32("ProcessID")
                    .or_else(|| info.get_u32("ProcessId"))
                    .or_else(|| read_raw_userdata_u32_at_0(record).filter(|&p| p != 0))
                else {
                    tracing::debug!(
                        version = record.EventHeader.EventDescriptor.Version,
                        user_data_len = record.UserDataLength,
                        "Kernel-Process ProcessStart missing ProcessID property"
                    );
                    return None;
                };
                let parent_pid = info
                    .get_u32("ParentProcessID")
                    .or_else(|| info.get_u32("ParentProcessId"))
                    .unwrap_or(record.EventHeader.ProcessId);
                let create_time_100ns = info.get_u64("CreateTime").unwrap_or(0);
                let exe_path = info
                    .get_string("ImageName")
                    .or_else(|| info.get_string("ImageFileName"))
                    .map(|raw| ctx.volume_map.normalize_path(&raw))
                    .unwrap_or_default();
                let command_line = info.get_string("CommandLine").unwrap_or_default();
                let user_sid = info.get_sid_string("UserSID");
                (
                    pid,
                    parent_pid,
                    create_time_100ns,
                    exe_path,
                    command_line,
                    user_sid,
                )
            }
            Err(tdh_status) => {
                let fail_count = KERNEL_PROCESS_TDH_FAILURES.fetch_add(1, Ordering::Relaxed) + 1;
                if fail_count.is_power_of_two() {
                    tracing::warn!(
                        tdh_status,
                        fail_count,
                        event_id = record.EventHeader.EventDescriptor.Id,
                        version = record.EventHeader.EventDescriptor.Version,
                        user_data_len = record.UserDataLength,
                        "TdhGetEventInformation failed for Kernel-Process ProcessStart; using raw UserData + Win32 fallback"
                    );
                }
                let pid = read_raw_userdata_u32_at_0(record).filter(|&p| p != 0)?;
                (
                    pid,
                    record.EventHeader.ProcessId,
                    0,
                    String::new(),
                    String::new(),
                    None,
                )
            }
        };

    ctx.evict_dns_pid(pid);

    let needs_inspect = create_time_100ns == 0 || exe_path.is_empty() || command_line.is_empty();
    let inspected = if needs_inspect {
        inspect_process_by_pid(pid, Some(&ctx.volume_map))
    } else {
        None
    };
    if let Some(inspected) = inspected {
        if create_time_100ns == 0 && inspected.create_time_100ns > 0 {
            create_time_100ns = inspected.create_time_100ns;
        }
        if exe_path.is_empty() {
            exe_path = inspected.exe_path.unwrap_or_default();
        }
        if command_line.is_empty() {
            command_line = inspected.command_line.unwrap_or_default();
        }
    }

    if create_time_100ns == 0 && record.EventHeader.TimeStamp > 0 {
        create_time_100ns = record.EventHeader.TimeStamp as u64;
    }

    let emitted = KERNEL_PROCESS_START_EMITTED.fetch_add(1, Ordering::Relaxed) + 1;
    if emitted.is_power_of_two() {
        tracing::debug!(
            emitted,
            pid,
            parent_pid,
            create_time_100ns,
            exe_path = %exe_path,
            "emitted ProcessStart from Kernel-Process ETW"
        );
    }

    Some(SensorEvent::ProcessStart {
        identity: ProcessIdentity::new(pid, create_time_100ns),
        parent_pid,
        exe_path,
        command_line,
        user_sid,
    })
}

fn handle_process_stop(record: &EVENT_RECORD, ctx: &EtwCallbackContext) -> Option<SensorEvent> {
    let (pid, exit_time_100ns, exit_code) = match TdhEventInfo::from_record_with_status(record) {
        Ok(info) => {
            let pid = info
                .get_u32("ProcessID")
                .or_else(|| info.get_u32("ProcessId"))
                .or_else(|| read_raw_userdata_u32_at_0(record).filter(|&p| p != 0))
                .unwrap_or(record.EventHeader.ProcessId);
            let exit_time_100ns = info
                .get_u64("ExitTime")
                .filter(|&t| t > 0)
                .unwrap_or_else(|| record.EventHeader.TimeStamp.max(0) as u64);
            let exit_code = info.get_u32("ExitCode").unwrap_or(0);
            (pid, exit_time_100ns, exit_code)
        }
        Err(tdh_status) => {
            let fail_count = KERNEL_PROCESS_TDH_FAILURES.fetch_add(1, Ordering::Relaxed) + 1;
            if fail_count.is_power_of_two() {
                tracing::warn!(
                    tdh_status,
                    fail_count,
                    event_id = record.EventHeader.EventDescriptor.Id,
                    version = record.EventHeader.EventDescriptor.Version,
                    user_data_len = record.UserDataLength,
                    "TdhGetEventInformation failed for Kernel-Process ProcessStop; using raw UserData fallback"
                );
            }
            let pid = read_raw_userdata_u32_at_0(record)
                .filter(|&p| p != 0)
                .unwrap_or(record.EventHeader.ProcessId);
            let exit_time_100ns = record.EventHeader.TimeStamp.max(0) as u64;
            (pid, exit_time_100ns, 0)
        }
    };
    ctx.evict_dns_pid(pid);

    let emitted = KERNEL_PROCESS_STOP_EMITTED.fetch_add(1, Ordering::Relaxed) + 1;
    if emitted.is_power_of_two() {
        tracing::debug!(
            emitted,
            pid,
            exit_time_100ns,
            exit_code,
            "emitted ProcessStop from Kernel-Process ETW"
        );
    }

    Some(SensorEvent::ProcessStop {
        pid,
        exit_time_100ns,
        exit_code,
    })
}

fn handle_dns_client(
    record: &EVENT_RECORD,
    event_id: u16,
    ctx: &EtwCallbackContext,
) -> Option<SensorEvent> {
    let info = TdhEventInfo::from_record(record)?;
    let query_name = info
        .get_string("QueryName")
        .map(|s| s.trim().trim_end_matches('.').to_string())
        .filter(|s| !s.is_empty())?;

    let results_raw = info.get_string("QueryResults").unwrap_or_default();
    let resolved_ips = parse_dns_query_results(&results_raw);
    if event_id == 3006 && resolved_ips.is_empty() {
        return None;
    }

    let query_type = info
        .get_u16("QueryType")
        .or_else(|| info.get_u32("QueryType").map(|v| v as u16))
        .unwrap_or(0);
    let timestamp_ms = filetime_100ns_to_unix_ms(record.EventHeader.TimeStamp.max(0) as u64);

    let pid = record.EventHeader.ProcessId;
    ctx.record_dns_resolution(pid, &query_name, &resolved_ips, timestamp_ms);

    Some(SensorEvent::DnsQuery {
        pid,
        query_name,
        query_type,
        resolved_ips,
        timestamp_ms,
    })
}

fn handle_kernel_network(
    record: &EVENT_RECORD,
    event_id: u16,
    ctx: &EtwCallbackContext,
) -> Option<SensorEvent> {
    let info = TdhEventInfo::from_record(record)?;
    let pid = info
        .get_u32("PID")
        .filter(|&p| p != 0)
        .unwrap_or(record.EventHeader.ProcessId);
    let dst_ip = info.get_ip_addr("daddr")?;
    let dst_port = info.get_port_be("dport")?;
    let protocol = if event_id == 12 || event_id == 28 { 6 } else { 17 };
    let timestamp_ms = filetime_100ns_to_unix_ms(record.EventHeader.TimeStamp.max(0) as u64);

    let domain_hint = ctx.resolve_network_domain_hint(pid, &dst_ip);

    Some(SensorEvent::NetworkConnect {
        pid,
        protocol,
        dst_ip,
        dst_port,
        domain_hint,
        timestamp_ms,
    })
}

fn handle_script_event(
    record: &EVENT_RECORD,
    source: ScriptSource,
    field_name: &str,
) -> Option<SensorEvent> {
    let info = TdhEventInfo::from_record(record)?;
    let script_content = info.get_string(field_name).filter(|s| !s.is_empty())?;
    let timestamp_ms = filetime_100ns_to_unix_ms(record.EventHeader.TimeStamp.max(0) as u64);

    Some(SensorEvent::ScriptEvaluated {
        pid: record.EventHeader.ProcessId,
        source,
        script_content,
        timestamp_ms,
    })
}

fn handle_kernel_file(
    record: &EVENT_RECORD,
    event_id: u16,
    ctx: &EtwCallbackContext,
) -> Option<SensorEvent> {
    const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;
    const WRITE_OR_DELETE_ACCESS_BITS: u32 = 0x4001_0006; // GENERIC_WRITE | DELETE | WRITE_DATA | APPEND_DATA

    match event_id {
        12 | 30 | 26 | 27 | 28 => {
            let pid = record.EventHeader.ProcessId;
            if pid == 0 || pid == u32::MAX {
                return None;
            }
            let info = TdhEventInfo::from_record(record)?;
            let (is_write_or_delete, access_mask) = match event_id {
                12 => {
                    let create_options = info.get_u32("CreateOptions").unwrap_or(0);
                    let desired_access = info.get_u32("DesiredAccess");
                    let disposition = (create_options >> 24) & 0xFF;
                    let write_disp = matches!(disposition, 0 | 2 | 4 | 5);
                    let delete_on_close = (create_options & FILE_DELETE_ON_CLOSE) != 0;
                    let write_access =
                        desired_access.is_some_and(|a| (a & WRITE_OR_DELETE_ACCESS_BITS) != 0);
                    (
                        write_disp || delete_on_close || write_access,
                        desired_access.unwrap_or(create_options),
                    )
                }
                30 => (true, info.get_u32("CreateOptions").unwrap_or(0)),
                _ => (true, info.get_u32("InfoClass").unwrap_or(0)),
            };

            let prop_names: &[&str] = match event_id {
                26..=28 => &["FilePath", "FileName", "OpenPath"],
                _ => &["FileName", "OpenPath", "FilePath"],
            };

            let matched = {
                let matcher = ctx.canary_matcher.read().unwrap_or_else(|e| e.into_inner());
                info.inspect_first_utf16_property(prop_names, |u16_slice| {
                    if let Some(cat) =
                        matcher.classify_u16(u16_slice, &ctx.volume_map, is_write_or_delete)
                    {
                        return Some((cat, ctx.volume_map.normalize_u16(u16_slice), false));
                    }
                    // Track read/existing opens of honeypot files without alerting so a
                    // subsequent Write/SetDelete/Rename on the same FileObject is caught (L-06).
                    if event_id == 12
                        && !is_write_or_delete
                        && matcher.is_honeypot_u16(u16_slice, &ctx.volume_map)
                    {
                        return Some((
                            CanaryCategory::Honeypot,
                            ctx.volume_map.normalize_u16(u16_slice),
                            true,
                        ));
                    }
                    None
                })?
            };

            let (category, target_path, track_only) = matched;
            if track_only {
                if let Some(file_object) = info.get_u64("FileObject") {
                    ctx.track_honeypot_handle(file_object, target_path);
                }
                return None;
            }

            let timestamp_ms =
                filetime_100ns_to_unix_ms(record.EventHeader.TimeStamp.max(0) as u64);
            Some(SensorEvent::CanaryFileAccess {
                pid,
                target_path,
                category,
                access_mask,
                is_write_or_delete,
                timestamp_ms,
            })
        }
        16 | 18 | 19 | 29 => {
            if !ctx.has_honeypot_handles.load(Ordering::Acquire) {
                return None;
            }
            let pid = record.EventHeader.ProcessId;
            if pid == 0 || pid == u32::MAX {
                return None;
            }
            let info = TdhEventInfo::from_record(record)?;
            let file_object = info.get_u64("FileObject")?;
            let target_path = ctx.trigger_honeypot_handle(file_object)?;
            let access_mask = info
                .get_u32("IOFlags")
                .or_else(|| info.get_u32("InfoClass"))
                .unwrap_or(event_id as u32);
            let timestamp_ms =
                filetime_100ns_to_unix_ms(record.EventHeader.TimeStamp.max(0) as u64);
            Some(SensorEvent::CanaryFileAccess {
                pid,
                target_path,
                category: CanaryCategory::Honeypot,
                access_mask,
                is_write_or_delete: true,
                timestamp_ms,
            })
        }
        14 => {
            if !ctx.has_honeypot_handles.load(Ordering::Acquire) {
                return None;
            }
            let info = TdhEventInfo::from_record(record)?;
            if let Some(file_object) = info.get_u64("FileObject") {
                ctx.close_honeypot_handle(file_object);
            }
            None
        }
        _ => None,
    }
}
