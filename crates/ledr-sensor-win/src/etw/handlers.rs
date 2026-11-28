//! ETW raw FFI callbacks and per-provider event handlers.

use std::sync::atomic::{AtomicU64, Ordering};

use ledr_proto::{CanaryCategory, ProcessIdentity, ScriptSource, SensorEvent};
use windows::core::GUID;
use windows::Win32::System::Diagnostics::Etw::{EVENT_RECORD, EVENT_TRACE_LOGFILEW};

use super::ProcessPackageInfo;
use super::cmdline_correlator::{
    PendingKernelStart, SystemProcessCommandLine, TakeOrRegisterOutcome,
};
use super::context::{AuxSystemProcessContext, EtwCallbackContext};
use super::registry::handle_kernel_registry;
use super::tdh::{
    ProcessInspectInfo, TdhEventInfo, filetime_100ns_to_unix_ms, inspect_process_by_pid,
    inspect_process_package_by_pid, parse_dns_query_results,
};

static KERNEL_PROCESS_RECEIVED: AtomicU64 = AtomicU64::new(0);
static KERNEL_PROCESS_TDH_FAILURES: AtomicU64 = AtomicU64::new(0);
static KERNEL_PROCESS_START_EMITTED: AtomicU64 = AtomicU64::new(0);
static KERNEL_PROCESS_STOP_EMITTED: AtomicU64 = AtomicU64::new(0);
static SYSTEM_PROCESS_RECEIVED: AtomicU64 = AtomicU64::new(0);
static SYSTEM_PROCESS_TDH_FAILURES: AtomicU64 = AtomicU64::new(0);
static SYSTEM_PROCESS_CORRELATED: AtomicU64 = AtomicU64::new(0);

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
/// Classic kernel MOF `Process` provider (`{3D6FA8D0-FE05-11D0-9DDA-00C04FD7BA7C}`).
pub(super) const SYSTEM_PROCESS_MOF_GUID: GUID =
    GUID::from_u128(0x3d6fa8d0_fe05_11d0_9dda_00c04fd7ba7c);

#[inline]
fn log_correlated_cmdline(path_label: &'static str, pid: u32, delta_100ns: i128) {
    let count = SYSTEM_PROCESS_CORRELATED.fetch_add(1, Ordering::Relaxed) + 1;
    if count.is_power_of_two() {
        tracing::debug!(
            correlated = count,
            path = path_label,
            pid,
            delta_ms = (delta_100ns as f64) / 10_000.0,
            "correlated SystemTrace kernel CommandLine with Kernel-Process ProcessStart"
        );
    }
}

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
        if event_id == 1 {
            if let Some((event, package)) = handle_process_start(record, ctx) {
                dispatch_process_start_with_correlator_and_package(ctx, event, package);
            }
            return;
        }
        match event_id {
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

trait ProcessStartPropertySource {
    fn get_u32(&self, name: &str) -> Option<u32>;
    fn get_u64(&self, name: &str) -> Option<u64>;
    fn get_string(&self, name: &str) -> Option<String>;
    fn get_sid_string(&self, name: &str) -> Option<String>;
}

impl ProcessStartPropertySource for TdhEventInfo<'_> {
    fn get_u32(&self, name: &str) -> Option<u32> {
        TdhEventInfo::get_u32(self, name)
    }

    fn get_u64(&self, name: &str) -> Option<u64> {
        TdhEventInfo::get_u64(self, name)
    }

    fn get_string(&self, name: &str) -> Option<String> {
        TdhEventInfo::get_string(self, name)
    }

    fn get_sid_string(&self, name: &str) -> Option<String> {
        TdhEventInfo::get_sid_string(self, name)
    }
}

fn handle_process_start(
    record: &EVENT_RECORD,
    ctx: &EtwCallbackContext,
) -> Option<(SensorEvent, ProcessPackageInfo)> {
    build_process_start_event_with_package(
        record,
        ctx,
        TdhEventInfo::from_record_with_status(record),
        |pid| inspect_process_by_pid(pid, Some(&ctx.volume_map)),
        inspect_process_package_by_pid,
    )
}

#[cfg(test)]
fn build_process_start_event<S, F>(
    record: &EVENT_RECORD,
    ctx: &EtwCallbackContext,
    tdh_result: Result<S, u32>,
    inspect_fn: F,
) -> Option<SensorEvent>
where
    S: ProcessStartPropertySource,
    F: FnOnce(u32) -> Option<ProcessInspectInfo>,
{
    build_process_start_event_with_package(record, ctx, tdh_result, inspect_fn, |_, _, _| None)
        .map(|(ev, _)| ev)
}

fn build_process_start_event_with_package<S, F, P>(
    record: &EVENT_RECORD,
    ctx: &EtwCallbackContext,
    tdh_result: Result<S, u32>,
    inspect_fn: F,
    inspect_package_fn: P,
) -> Option<(SensorEvent, ProcessPackageInfo)>
where
    S: ProcessStartPropertySource,
    F: FnOnce(u32) -> Option<ProcessInspectInfo>,
    P: FnOnce(u32, u64, Option<u64>) -> Option<ProcessPackageInfo>,
{
    let (pid, mut parent_pid, mut create_time_100ns, mut exe_path, mut command_line, user_sid) =
        match tdh_result {
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
                // Never substitute `EventHeader.ProcessId` when ETW omits the parent PID:
                // backfill via `inspect_process_by_pid` (`InheritedFromUniqueProcessId`) or leave
                // as `0` so same-instance snapshot enrichment remains unblocked.
                let parent_pid = info
                    .get_u32("ParentProcessID")
                    .or_else(|| info.get_u32("ParentProcessId"))
                    .unwrap_or(0);
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
                    // Leave parent_pid as 0 so live process inspection / snapshot can supply it.
                    0,
                    0,
                    String::new(),
                    String::new(),
                    None,
                )
            }
        };

    ctx.evict_dns_pid(pid);

    if command_line.is_empty() && create_time_100ns != 0 {
        let matched = {
            let mut correlator = ctx
                .cmdline_correlator
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            correlator.take_matching_command_line(pid, parent_pid, create_time_100ns, &exe_path)
        };
        if let Some(matched) = matched {
            command_line = matched.command_line;
            log_correlated_cmdline("path_a_fast", pid, matched.delta_100ns);
        }
    }

    let mut package = ProcessPackageInfo::default();
    let needs_inspect = parent_pid == 0
        || create_time_100ns == 0
        || exe_path.is_empty()
        || command_line.is_empty();
    let inspected = if needs_inspect {
        inspect_fn(pid)
    } else {
        None
    };
    if let Some(inspected) = inspected {
        // Verify process generation before merging live attributes:
        // - When ETW provided `CreateTime`, require an exact 100ns match.
        // - When `CreateTime` is missing (`0`), bound by `EventHeader.TimeStamp`
        //   (FILETIME 100ns under `ClientContext = 2`) to reject newer PID-reused processes.
        // - When both timestamps are absent, fail closed.
        let same_incarnation = if create_time_100ns != 0 {
            inspected.create_time_100ns == create_time_100ns
        } else if record.EventHeader.TimeStamp > 0 {
            let event_ts_100ns = record.EventHeader.TimeStamp as u64;
            inspected.create_time_100ns > 0 && inspected.create_time_100ns <= event_ts_100ns
        } else {
            false
        };
        if same_incarnation {
            if parent_pid == 0 {
                if let Some(inspected_ppid) = inspected.parent_pid {
                    parent_pid = inspected_ppid;
                }
            }
            if create_time_100ns == 0 && inspected.create_time_100ns > 0 {
                create_time_100ns = inspected.create_time_100ns;
            }
            if exe_path.is_empty() {
                exe_path = inspected.exe_path.unwrap_or_default();
            }
            if command_line.is_empty() {
                command_line = inspected.command_line.unwrap_or_default();
            }
            package = ProcessPackageInfo {
                package_family_name: inspected.package_family_name,
                package_sid: inspected.package_sid,
            }
            .normalized();
        }
    } else if !needs_inspect {
        let max_event_ts = (record.EventHeader.TimeStamp > 0)
            .then_some(record.EventHeader.TimeStamp as u64);
        if let Some(pkg) = inspect_package_fn(pid, create_time_100ns, max_event_ts) {
            package = pkg.normalized();
        }
    }

    if create_time_100ns == 0 && record.EventHeader.TimeStamp > 0 {
        create_time_100ns = record.EventHeader.TimeStamp as u64;
    }

    if command_line.is_empty() && create_time_100ns != 0 {
        let matched = {
            let mut correlator = ctx
                .cmdline_correlator
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            correlator.take_matching_command_line(pid, parent_pid, create_time_100ns, &exe_path)
        };
        if let Some(matched) = matched {
            command_line = matched.command_line;
            log_correlated_cmdline("path_a_post_inspect", pid, matched.delta_100ns);
        }
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

    Some((
        SensorEvent::ProcessStart {
            identity: ProcessIdentity::new(pid, create_time_100ns),
            parent_pid,
            exe_path,
            command_line,
            user_sid,
        },
        package,
    ))
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

#[cfg(test)]
fn dispatch_process_start_with_correlator(ctx: &EtwCallbackContext, event: SensorEvent) {
    dispatch_process_start_with_correlator_and_package(ctx, event, ProcessPackageInfo::default());
}

fn dispatch_process_start_with_correlator_and_package(
    ctx: &EtwCallbackContext,
    event: SensorEvent,
    package: ProcessPackageInfo,
) {
    let pending = match &event {
        SensorEvent::ProcessStart {
            identity,
            parent_pid,
            exe_path,
            command_line,
            user_sid,
        } if command_line.is_empty()
            && identity.create_time_100ns != 0
            && ctx.aux_active.load(Ordering::Acquire) =>
        {
            Some(PendingKernelStart {
                pid: identity.pid,
                create_time_100ns: identity.create_time_100ns,
                parent_pid: *parent_pid,
                exe_path: exe_path.clone(),
                user_sid: user_sid.clone(),
                package: package.clone(),
            })
        }
        _ => None,
    };

    if !ctx.dispatch_event_with_package(event, package) {
        return;
    }

    if let Some(pending) = pending {
        let outcome = {
            let mut correlator = ctx
                .cmdline_correlator
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            correlator.take_or_register_pending_start(pending)
        };
        if let TakeOrRegisterOutcome::Matched { pending, matched } = outcome {
            log_correlated_cmdline("path_b_race_resolved", pending.pid, matched.delta_100ns);
            let enriched = SensorEvent::ProcessStart {
                identity: ProcessIdentity::new(pending.pid, pending.create_time_100ns),
                parent_pid: pending.parent_pid,
                exe_path: pending.exe_path,
                command_line: matched.command_line,
                user_sid: pending.user_sid,
            };
            let _ = ctx.dispatch_event_with_package(enriched, pending.package);
        }
    }
}

trait SystemProcessPropertySource {
    fn get_u32(&self, name: &str) -> Option<u32>;
    fn get_string(&self, name: &str) -> Option<String>;
}

impl SystemProcessPropertySource for TdhEventInfo<'_> {
    fn get_u32(&self, name: &str) -> Option<u32> {
        TdhEventInfo::get_u32(self, name)
    }

    fn get_string(&self, name: &str) -> Option<String> {
        TdhEventInfo::get_string(self, name)
    }
}

pub(super) unsafe extern "system" fn aux_buffer_callback(logfile: *mut EVENT_TRACE_LOGFILEW) -> u32 {
    if logfile.is_null() {
        return 0;
    }
    // SAFETY: `logfile` is non-null and provided by ETW runtime.
    let ctx_ptr = unsafe { (*logfile).Context.cast::<AuxSystemProcessContext>() };
    if ctx_ptr.is_null() {
        return 1;
    }
    // SAFETY: `ctx_ptr` remains valid for the lifetime of auxiliary `ProcessTrace`.
    let ctx = unsafe { &*ctx_ptr };
    if ctx.stop_requested.load(Ordering::Acquire) {
        0
    } else {
        1
    }
}

pub(super) unsafe extern "system" fn aux_system_process_callback(event_record: *mut EVENT_RECORD) {
    if event_record.is_null() {
        return;
    }
    // SAFETY: `event_record` is non-null and valid for the callback duration.
    let record = unsafe { &*event_record };
    let ctx_ptr = record.UserContext.cast::<AuxSystemProcessContext>();
    if ctx_ptr.is_null() {
        return;
    }
    // SAFETY: `ctx_ptr` remains valid until after auxiliary `ProcessTrace` exits.
    let ctx = unsafe { &*ctx_ptr };
    if ctx.stop_requested.load(Ordering::Acquire) {
        return;
    }
    if record.EventHeader.ProviderId != SYSTEM_PROCESS_MOF_GUID
        || record.EventHeader.EventDescriptor.Opcode != 1
    {
        return;
    }

    let received = SYSTEM_PROCESS_RECEIVED.fetch_add(1, Ordering::Relaxed) + 1;
    if received.is_power_of_two() {
        tracing::debug!(
            received,
            version = record.EventHeader.EventDescriptor.Version,
            user_data_len = record.UserDataLength,
            "received SystemTrace Process Start ETW event"
        );
    }

    if let Some((enriched, package)) =
        handle_system_process_start(record, ctx, TdhEventInfo::from_record_with_status(record))
    {
        let _ = ctx.dispatch_event_with_package(enriched, package);
    }
}

fn handle_system_process_start<S>(
    record: &EVENT_RECORD,
    ctx: &AuxSystemProcessContext,
    tdh_result: Result<S, u32>,
) -> Option<(SensorEvent, ProcessPackageInfo)>
where
    S: SystemProcessPropertySource,
{
    let info = match tdh_result {
        Ok(info) => info,
        Err(tdh_status) => {
            let fail_count = SYSTEM_PROCESS_TDH_FAILURES.fetch_add(1, Ordering::Relaxed) + 1;
            if fail_count.is_power_of_two() {
                tracing::warn!(
                    tdh_status,
                    fail_count,
                    version = record.EventHeader.EventDescriptor.Version,
                    user_data_len = record.UserDataLength,
                    "TdhGetEventInformation failed for SystemTrace Process Start; dropping event"
                );
            }
            return None;
        }
    };

    if record.EventHeader.TimeStamp <= 0 {
        return None;
    }
    let event_ts_100ns = record.EventHeader.TimeStamp as u64;
    let pid = info
        .get_u32("ProcessId")
        .or_else(|| info.get_u32("ProcessID"))
        .filter(|&p| p != 0)?;
    let parent_pid = info
        .get_u32("ParentId")
        .or_else(|| info.get_u32("ParentProcessId"))
        .unwrap_or(0);
    let image_short_name = info.get_string("ImageFileName").unwrap_or_default();
    let command_line = info.get_string("CommandLine").unwrap_or_default();
    if command_line.trim().is_empty() {
        return None;
    }

    let resolved = {
        let mut correlator = ctx
            .cmdline_correlator
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        correlator.on_system_process_start(SystemProcessCommandLine {
            pid,
            parent_pid,
            event_ts_100ns,
            image_short_name,
            command_line,
        })
    }?;

    log_correlated_cmdline(
        "path_b_delayed",
        resolved.pending.pid,
        resolved.delta_100ns,
    );
    Some((
        SensorEvent::ProcessStart {
            identity: ProcessIdentity::new(
                resolved.pending.pid,
                resolved.pending.create_time_100ns,
            ),
            parent_pid: resolved.pending.parent_pid,
            exe_path: resolved.pending.exe_path,
            command_line: resolved.command_line,
            user_sid: resolved.pending.user_sid,
        },
        resolved.pending.package,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex, RwLock};

    use crate::dns_cache::DnsResolutionCache;
    use crate::path_norm::DosVolumeMap;

    use super::super::cmdline_correlator::ProcessCommandLineCorrelator;
    use super::super::context::HoneypotHandleTracker;
    use super::super::file_canary::CanaryMatcher;
    use super::super::session::PackageAwareEventSinkFn;
    use super::super::snapshot::try_capture_running_processes;

    fn dummy_etw_ctx() -> EtwCallbackContext {
        let sink: PackageAwareEventSinkFn = Arc::new(|_, _| true);
        EtwCallbackContext {
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
        }
    }

    struct StubPropertySource {
        pid: Option<u32>,
        parent_pid: Option<u32>,
        create_time_100ns: Option<u64>,
        image_name: Option<String>,
        command_line: Option<String>,
    }

    impl ProcessStartPropertySource for StubPropertySource {
        fn get_u32(&self, name: &str) -> Option<u32> {
            match name {
                "ProcessID" | "ProcessId" => self.pid,
                "ParentProcessID" | "ParentProcessId" => self.parent_pid,
                _ => None,
            }
        }

        fn get_u64(&self, name: &str) -> Option<u64> {
            match name {
                "CreateTime" => self.create_time_100ns,
                _ => None,
            }
        }

        fn get_string(&self, name: &str) -> Option<String> {
            match name {
                "ImageName" | "ImageFileName" => self.image_name.clone(),
                "CommandLine" => self.command_line.clone(),
                _ => None,
            }
        }

        fn get_sid_string(&self, _name: &str) -> Option<String> {
            None
        }
    }

    /// `PR23-R30-T1-01`: When ETW fails and live inspection cannot resolve the process,
    /// `handle_process_start` must emit `parent_pid = 0` rather than substituting
    /// `record.EventHeader.ProcessId`.
    #[test]
    fn sens_p3_15_pr23_r30_t1_process_start_missing_parent_pid_does_not_substitute_header_pid() {
        let ctx = dummy_etw_ctx();

        // 4-byte aligned non-existent dummy PID so `inspect_process_by_pid` returns `None`.
        let child_pid: u32 = 0xFFFF_FFFC;
        let mut user_data = child_pid.to_le_bytes();
        let mut record = EVENT_RECORD::default();
        record.EventHeader.ProcessId = 800;
        record.EventHeader.EventDescriptor.Id = 1;
        record.UserData = user_data.as_mut_ptr().cast();
        record.UserDataLength = user_data.len() as u16;

        let (event, _pkg) = handle_process_start(&record, &ctx)
            .expect("ProcessStart with valid UserData PID should emit event");
        match event {
            SensorEvent::ProcessStart {
                identity,
                parent_pid,
                ..
            } => {
                assert_eq!(identity.pid, child_pid);
                assert_eq!(
                    parent_pid, 0,
                    "missing ETW parent PID must remain 0 instead of using EventHeader.ProcessId"
                );
            }
            other => panic!("expected ProcessStart, got {other:?}"),
        }
    }

    /// `PR23-R33-T1-01`: `inspect_process_by_pid` must query `InheritedFromUniqueProcessId`
    /// via `NtQueryInformationProcess(ProcessBasicInformation)` and agree with Toolhelp32 snapshot.
    #[test]
    fn sens_p3_16_pr23_r33_t1_inspect_process_parent_pid_matches_toolhelp_snapshot() {
        let self_pid = std::process::id();
        let inspected = inspect_process_by_pid(self_pid, None)
            .expect("inspect_process_by_pid must resolve current process");
        let ppid = inspected
            .parent_pid
            .expect("current process must resolve non-zero InheritedFromUniqueProcessId");
        assert_ne!(ppid, 0);
        assert_ne!(ppid, self_pid);

        let snap = try_capture_running_processes().expect("Toolhelp32 snapshot succeeds");
        let snap_ppid = snap
            .into_iter()
            .find_map(|ev| match ev {
                SensorEvent::ProcessStart {
                    identity,
                    parent_pid,
                    ..
                } if identity.pid == self_pid => Some(parent_pid),
                _ => None,
            })
            .expect("current process must appear in Toolhelp32 snapshot");
        assert_eq!(ppid, snap_ppid);
    }

    /// `PR23-R33-T1-02`: On TDH metadata failure (`Err`) for a live process,
    /// `handle_process_start` must backfill the OS parent PID via `inspect_process_by_pid`
    /// instead of using `EventHeader.ProcessId` or leaving `parent_pid = 0`.
    #[test]
    fn sens_p3_17_pr23_r33_t1_tdh_failure_backfills_parent_pid_from_live_process() {
        let ctx = dummy_etw_ctx();
        let self_pid = std::process::id();
        let expected_info = inspect_process_by_pid(self_pid, None)
            .expect("inspect_process_by_pid resolves current process");
        let expected_ppid = expected_info
            .parent_pid
            .expect("current process has non-zero OS parent PID");

        let dummy_header_pid: u32 = 0xFFFF_FFF8;
        assert_ne!(expected_ppid, dummy_header_pid);

        let mut user_data = self_pid.to_le_bytes();
        let mut record = EVENT_RECORD::default();
        record.EventHeader.ProcessId = dummy_header_pid;
        record.EventHeader.TimeStamp = expected_info.create_time_100ns as i64;
        record.EventHeader.EventDescriptor.Id = 1;
        record.UserData = user_data.as_mut_ptr().cast();
        record.UserDataLength = user_data.len() as u16;

        let (event, _pkg) = handle_process_start(&record, &ctx)
            .expect("handle_process_start must emit event for live self PID");
        match event {
            SensorEvent::ProcessStart {
                identity,
                parent_pid,
                ..
            } => {
                assert_eq!(identity.pid, self_pid);
                assert!(identity.create_time_100ns > 0);
                assert_eq!(
                    parent_pid, expected_ppid,
                    "TDH failure fallback must use OS InheritedFromUniqueProcessId, not EventHeader.ProcessId"
                );
            }
            other => panic!("expected ProcessStart, got {other:?}"),
        }
    }

    /// `PR23-R33-T2-01`: When TDH succeeds (`Ok`) and provides `ProcessID`/`CreateTime`/paths
    /// but omits `ParentProcessID`/`ParentProcessId`, `build_process_start_event` must:
    /// (a) backfill `parent_pid` when live inspection confirms the same `create_time_100ns`,
    /// (b) leave `parent_pid = 0` when live inspection returns `None` (never using header PID),
    /// (c) reject live inspection with a mismatched `create_time_100ns` (PID reuse).
    #[test]
    fn sens_p3_18_pr23_r33_t2_tdh_ok_missing_parent_pid_uses_verified_live_inspect_not_header_pid()
    {
        let ctx = dummy_etw_ctx();
        let mut record = EVENT_RECORD::default();
        record.EventHeader.ProcessId = 800;
        record.EventHeader.EventDescriptor.Id = 1;

        let make_props = || StubPropertySource {
            pid: Some(4242),
            parent_pid: None,
            create_time_100ns: Some(133_800_000_000_000_000),
            image_name: Some(r"\Device\HarddiskVolume1\Tools\app.exe".to_string()),
            command_line: Some("app.exe --run".to_string()),
        };

        // (a) Same creation time: live inspection supplies the OS parent PID (1200).
        let ev_same = build_process_start_event(&record, &ctx, Ok(make_props()), |_| {
            Some(ProcessInspectInfo {
                parent_pid: Some(1200),
                create_time_100ns: 133_800_000_000_000_000,
                exe_path: Some(r"C:\Tools\app.exe".to_string()),
                command_line: Some("app.exe --run".to_string()),
                package_family_name: None,
                package_sid: None,
            })
        })
        .expect("event emitted on same incarnation");
        match ev_same {
            SensorEvent::ProcessStart { parent_pid, .. } => assert_eq!(parent_pid, 1200),
            other => panic!("expected ProcessStart, got {other:?}"),
        }

        // (b) Live inspection returns None: parent_pid stays 0, never EventHeader.ProcessId (800).
        let ev_none = build_process_start_event(&record, &ctx, Ok(make_props()), |_| None)
            .expect("event emitted when inspect returns None");
        match ev_none {
            SensorEvent::ProcessStart { parent_pid, .. } => assert_eq!(parent_pid, 0),
            other => panic!("expected ProcessStart, got {other:?}"),
        }

        // (c) Mismatched creation time (PID reused by a newer process): reject live inspection.
        let ev_reused = build_process_start_event(&record, &ctx, Ok(make_props()), |_| {
            Some(ProcessInspectInfo {
                parent_pid: Some(7777),
                create_time_100ns: 133_800_000_999_000_000,
                exe_path: Some(r"C:\Tools\other.exe".to_string()),
                command_line: Some("other.exe".to_string()),
                package_family_name: None,
                package_sid: None,
            })
        })
        .expect("event emitted when inspect sees reused PID");
        match ev_reused {
            SensorEvent::ProcessStart { parent_pid, .. } => assert_eq!(parent_pid, 0),
            other => panic!("expected ProcessStart, got {other:?}"),
        }
    }

    /// `PR23-R36-T1-01`: When `CreateTime` is missing (`0`), live inspection must verify
    /// `0 < inspected.create_time_100ns <= EventHeader.TimeStamp` (and fail closed when
    /// `EventHeader.TimeStamp <= 0`) across both TDH `Ok` and TDH `Err` paths so a newer
    /// process that reused the PID cannot supply `parent_pid` or launch metadata.
    #[test]
    fn sens_p3_19_pr23_r36_t1_missing_create_time_bounds_live_inspect_by_event_timestamp() {
        let ctx = dummy_etw_ctx();
        let event_ts_100ns: u64 = 133_800_000_005_000_000;
        let earlier_create_100ns: u64 = 133_800_000_000_000_000;
        let newer_reused_create_100ns: u64 = 133_800_000_009_000_000;

        let mut user_data = 4242u32.to_le_bytes();
        let mut record = EVENT_RECORD::default();
        record.EventHeader.ProcessId = 800;
        record.EventHeader.TimeStamp = event_ts_100ns as i64;
        record.EventHeader.EventDescriptor.Id = 1;
        record.UserData = user_data.as_mut_ptr().cast();
        record.UserDataLength = user_data.len() as u16;

        let make_props_no_ct = || StubPropertySource {
            pid: Some(4242),
            parent_pid: None,
            create_time_100ns: None,
            image_name: None,
            command_line: None,
        };
        let older_inspect = || {
            Some(ProcessInspectInfo {
                parent_pid: Some(1200),
                create_time_100ns: earlier_create_100ns,
                exe_path: Some(r"C:\Tools\legit.exe".to_string()),
                command_line: Some("legit.exe --ok".to_string()),
                package_family_name: None,
                package_sid: None,
            })
        };
        let newer_inspect = || {
            Some(ProcessInspectInfo {
                parent_pid: Some(7777),
                create_time_100ns: newer_reused_create_100ns,
                exe_path: Some(r"C:\Tools\reused.exe".to_string()),
                command_line: Some("reused.exe --after".to_string()),
                package_family_name: None,
                package_sid: None,
            })
        };

        // (a) TDH Ok + missing CreateTime, inspected created <= event timestamp -> accepted.
        let ev_ok_valid =
            build_process_start_event(&record, &ctx, Ok(make_props_no_ct()), |_| older_inspect())
                .expect("tdh Ok with valid bounded inspect emits event");
        match ev_ok_valid {
            SensorEvent::ProcessStart {
                identity,
                parent_pid,
                exe_path,
                command_line,
                ..
            } => {
                assert_eq!(identity.create_time_100ns, earlier_create_100ns);
                assert_eq!(parent_pid, 1200);
                assert_eq!(exe_path, r"C:\Tools\legit.exe");
                assert_eq!(command_line, "legit.exe --ok");
            }
            other => panic!("expected ProcessStart, got {other:?}"),
        }

        // (b-1) TDH Ok + missing CreateTime, inspected created > event timestamp -> rejected.
        let ev_ok_reused =
            build_process_start_event(&record, &ctx, Ok(make_props_no_ct()), |_| newer_inspect())
                .expect("tdh Ok with reused PID inspect emits event without reused metadata");
        match ev_ok_reused {
            SensorEvent::ProcessStart {
                identity,
                parent_pid,
                exe_path,
                command_line,
                ..
            } => {
                assert_eq!(identity.create_time_100ns, event_ts_100ns);
                assert_eq!(parent_pid, 0);
                assert!(exe_path.is_empty());
                assert!(command_line.is_empty());
            }
            other => panic!("expected ProcessStart, got {other:?}"),
        }

        // (b-2) TDH Err, inspected created > event timestamp -> rejected.
        let ev_err_reused = build_process_start_event::<StubPropertySource, _>(
            &record,
            &ctx,
            Err(1168),
            |_| newer_inspect(),
        )
        .expect("tdh Err with reused PID inspect emits event without reused metadata");
        match ev_err_reused {
            SensorEvent::ProcessStart {
                identity,
                parent_pid,
                exe_path,
                command_line,
                ..
            } => {
                assert_eq!(identity.create_time_100ns, event_ts_100ns);
                assert_eq!(parent_pid, 0);
                assert!(exe_path.is_empty());
                assert!(command_line.is_empty());
            }
            other => panic!("expected ProcessStart, got {other:?}"),
        }

        // (c) Both CreateTime and EventHeader.TimeStamp absent -> fail closed.
        let mut no_ts_record = record;
        no_ts_record.EventHeader.TimeStamp = 0;
        let ev_no_ts =
            build_process_start_event(&no_ts_record, &ctx, Ok(make_props_no_ct()), |_| {
                older_inspect()
            })
            .expect("missing both timestamps still emits event without unverified live inspect");
        match ev_no_ts {
            SensorEvent::ProcessStart {
                identity,
                parent_pid,
                exe_path,
                command_line,
                ..
            } => {
                assert_eq!(identity.create_time_100ns, 0);
                assert_eq!(parent_pid, 0);
                assert!(exe_path.is_empty());
                assert!(command_line.is_empty());
            }
            other => panic!("expected ProcessStart, got {other:?}"),
        }
    }

    struct StubSysProcSource {
        pid: Option<u32>,
        parent_pid: Option<u32>,
        image_file_name: Option<String>,
        command_line: Option<String>,
    }

    impl SystemProcessPropertySource for StubSysProcSource {
        fn get_u32(&self, name: &str) -> Option<u32> {
            match name {
                "ProcessId" | "ProcessID" => self.pid,
                "ParentId" | "ParentProcessId" => self.parent_pid,
                _ => None,
            }
        }

        fn get_string(&self, name: &str) -> Option<String> {
            match name {
                "ImageFileName" => self.image_file_name.clone(),
                "CommandLine" => self.command_line.clone(),
                _ => None,
            }
        }
    }

    fn make_capturing_contexts(
        aux_active_init: bool,
    ) -> (
        EtwCallbackContext,
        AuxSystemProcessContext,
        Arc<Mutex<Vec<SensorEvent>>>,
    ) {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let captured_sink = Arc::clone(&captured);
        let sink: PackageAwareEventSinkFn = Arc::new(move |ev, _| {
            captured_sink
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(ev);
            true
        });
        let correlator = Arc::new(Mutex::new(ProcessCommandLineCorrelator::new()));
        let stop_requested = Arc::new(AtomicBool::new(false));
        let aux_active = Arc::new(AtomicBool::new(aux_active_init));
        let main_ctx = EtwCallbackContext {
            sink: Arc::clone(&sink),
            dns_cache: Mutex::new(DnsResolutionCache::default()),
            volume_map: DosVolumeMap::with_mappings(Vec::new()),
            canary_matcher: Arc::new(RwLock::new(CanaryMatcher::default())),
            honeypot_handles: Mutex::new(HoneypotHandleTracker::default()),
            has_honeypot_handles: AtomicBool::new(false),
            registry_kcb_names: Mutex::new(HashMap::new()),
            cmdline_correlator: Arc::clone(&correlator),
            aux_active: Arc::clone(&aux_active),
            stop_requested: Arc::clone(&stop_requested),
            session_name_nul: vec![0],
        };
        let aux_ctx = AuxSystemProcessContext {
            sink,
            cmdline_correlator: correlator,
            stop_requested,
            aux_active,
            session_name_nul: vec![0],
        };
        (main_ctx, aux_ctx, captured)
    }

    /// `ETW-P4-CMD-01`: Path A (`SystemTrace` arrives before `Kernel-Process` Event 1) ->
    /// `inspect_fn` is called 0 times and a single `ProcessStart` with kernel `command_line` is emitted.
    #[test]
    fn etw_p4_cmd_01_path_a_system_trace_first_skips_peb_and_emits_single_start() {
        use std::sync::atomic::AtomicUsize;

        let (main_ctx, aux_ctx, captured) = make_capturing_contexts(true);
        let create_ts: u64 = 133_800_000_000_000_000;

        let mut sys_record = EVENT_RECORD::default();
        sys_record.EventHeader.TimeStamp = (create_ts + 25_000) as i64;
        sys_record.EventHeader.ProviderId = SYSTEM_PROCESS_MOF_GUID;
        sys_record.EventHeader.EventDescriptor.Opcode = 1;

        assert!(handle_system_process_start(
            &sys_record,
            &aux_ctx,
            Ok(StubSysProcSource {
                pid: Some(4242),
                parent_pid: Some(1200),
                image_file_name: Some("cmd.exe".to_string()),
                command_line: Some("cmd.exe /c powershell.exe -enc SQBFAFgA".to_string()),
            })
        )
        .is_none());

        let mut kp_record = EVENT_RECORD::default();
        kp_record.EventHeader.TimeStamp = create_ts as i64;
        kp_record.EventHeader.EventDescriptor.Id = 1;
        let inspect_calls = AtomicUsize::new(0);
        let ev = build_process_start_event(
            &kp_record,
            &main_ctx,
            Ok(StubPropertySource {
                pid: Some(4242),
                parent_pid: Some(1200),
                create_time_100ns: Some(create_ts),
                image_name: Some(r"C:\Windows\System32\cmd.exe".to_string()),
                command_line: None,
            }),
            |_| {
                inspect_calls.fetch_add(1, Ordering::Relaxed);
                None
            },
        )
        .expect("ProcessStart emitted");

        assert_eq!(inspect_calls.load(Ordering::Relaxed), 0);
        dispatch_process_start_with_correlator(&main_ctx, ev);

        let events = captured.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(events.len(), 1);
        match &events[0] {
            SensorEvent::ProcessStart {
                identity,
                command_line,
                exe_path,
                ..
            } => {
                assert_eq!(identity, &ProcessIdentity::new(4242, create_ts));
                assert_eq!(exe_path, r"C:\Windows\System32\cmd.exe");
                assert_eq!(command_line, "cmd.exe /c powershell.exe -enc SQBFAFgA");
            }
            other => panic!("expected ProcessStart, got {other:?}"),
        }
    }

    /// `ETW-P4-CMD-02`: Path B (`Kernel-Process` Event 1 arrives first, PEB returns `None`,
    /// then `SystemTrace` arrives) -> initial `ProcessStart` emitted first, then enriched
    /// `ProcessStart` preserving exact `create_time_100ns` and full `exe_path`.
    #[test]
    fn etw_p4_cmd_02_path_b_kernel_first_then_system_trace_emits_enriched_start() {
        let (main_ctx, aux_ctx, captured) = make_capturing_contexts(true);
        let create_ts: u64 = 133_800_000_000_000_000;

        let mut kp_record = EVENT_RECORD::default();
        kp_record.EventHeader.TimeStamp = create_ts as i64;
        kp_record.EventHeader.EventDescriptor.Id = 1;
        let ev = build_process_start_event(
            &kp_record,
            &main_ctx,
            Ok(StubPropertySource {
                pid: Some(5252),
                parent_pid: Some(1200),
                create_time_100ns: Some(create_ts),
                image_name: Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string()),
                command_line: None,
            }),
            |_| None,
        )
        .expect("initial ProcessStart emitted");
        dispatch_process_start_with_correlator(&main_ctx, ev);

        let mut sys_record = EVENT_RECORD::default();
        sys_record.EventHeader.TimeStamp = (create_ts + 40_000) as i64;
        sys_record.EventHeader.ProviderId = SYSTEM_PROCESS_MOF_GUID;
        sys_record.EventHeader.EventDescriptor.Opcode = 1;
        let (enriched, package) = handle_system_process_start(
            &sys_record,
            &aux_ctx,
            Ok(StubSysProcSource {
                pid: Some(5252),
                parent_pid: Some(1200),
                image_file_name: Some("powershell.exe".to_string()),
                command_line: Some("powershell.exe -EncodedCommand ZQBjAGgAbwA=".to_string()),
            }),
        )
        .expect("Path B produces enriched ProcessStart");
        assert!(aux_ctx.dispatch_event_with_package(enriched, package));

        let events = captured.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(events.len(), 2);
        match (&events[0], &events[1]) {
            (
                SensorEvent::ProcessStart {
                    identity: id0,
                    command_line: cmd0,
                    exe_path: exe0,
                    ..
                },
                SensorEvent::ProcessStart {
                    identity: id1,
                    command_line: cmd1,
                    exe_path: exe1,
                    ..
                },
            ) => {
                assert_eq!(id0, &ProcessIdentity::new(5252, create_ts));
                assert!(cmd0.is_empty());
                assert_eq!(id1, &ProcessIdentity::new(5252, create_ts));
                assert_eq!(exe1, exe0);
                assert_eq!(cmd1, "powershell.exe -EncodedCommand ZQBjAGgAbwA=");
            }
            other => panic!("expected two ProcessStart events, got {other:?}"),
        }
    }

    /// `ETW-P4-CMD-03`: TOCTOU race coverage:
    /// (a) `SystemTrace` arrives while `inspect_fn` is running -> second-chance lookup catches it
    ///     and emits ONE complete `ProcessStart`.
    /// (b) `SystemTrace` arrives while initial `dispatch_event` is running -> `take_or_register_pending_start`
    ///     resolves immediately and main thread emits initial THEN enriched `ProcessStart` (no ordering inversion).
    #[test]
    fn etw_p4_cmd_03_toctou_during_inspect_and_during_initial_dispatch() {
        let create_ts: u64 = 133_800_000_000_000_000;

        // Subcase (a): arrival during inspect_fn
        {
            let (main_ctx, aux_ctx, captured) = make_capturing_contexts(true);
            let mut kp_record = EVENT_RECORD::default();
            kp_record.EventHeader.TimeStamp = create_ts as i64;
            kp_record.EventHeader.EventDescriptor.Id = 1;

            let ev = build_process_start_event(
                &kp_record,
                &main_ctx,
                Ok(StubPropertySource {
                    pid: Some(6100),
                    parent_pid: Some(1200),
                    create_time_100ns: Some(create_ts),
                    image_name: Some(r"C:\Windows\System32\cmd.exe".to_string()),
                    command_line: None,
                }),
                |_| {
                    let mut sys_record = EVENT_RECORD::default();
                    sys_record.EventHeader.TimeStamp = (create_ts + 10_000) as i64;
                    assert!(handle_system_process_start(
                        &sys_record,
                        &aux_ctx,
                        Ok(StubSysProcSource {
                            pid: Some(6100),
                            parent_pid: Some(1200),
                            image_file_name: Some("cmd.exe".to_string()),
                            command_line: Some("cmd.exe /c during-inspect".to_string()),
                        })
                    )
                    .is_none());
                    None
                },
            )
            .expect("ProcessStart emitted");
            dispatch_process_start_with_correlator(&main_ctx, ev);

            let events = captured.lock().unwrap_or_else(|e| e.into_inner());
            assert_eq!(events.len(), 1);
            match &events[0] {
                SensorEvent::ProcessStart { command_line, .. } => {
                    assert_eq!(command_line, "cmd.exe /c during-inspect");
                }
                other => panic!("expected ProcessStart, got {other:?}"),
            }
            let corr = main_ctx
                .cmdline_correlator
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            assert_eq!(corr.cached_sys_len(), 0);
            assert_eq!(corr.pending_starts_len(), 0);
        }

        // Subcase (b): arrival during initial dispatch_event
        {
            let captured = Arc::new(Mutex::new(Vec::new()));
            let correlator = Arc::new(Mutex::new(ProcessCommandLineCorrelator::new()));
            let stop_requested = Arc::new(AtomicBool::new(false));
            let aux_active = Arc::new(AtomicBool::new(true));

            let aux_sink: PackageAwareEventSinkFn = Arc::new(|_, _| true);
            let aux_ctx = AuxSystemProcessContext {
                sink: aux_sink,
                cmdline_correlator: Arc::clone(&correlator),
                stop_requested: Arc::clone(&stop_requested),
                aux_active: Arc::clone(&aux_active),
                session_name_nul: vec![0],
            };

            let captured_sink = Arc::clone(&captured);
            let main_sink: PackageAwareEventSinkFn = Arc::new(move |ev, _| {
                let is_first = captured_sink
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .is_empty();
                captured_sink
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(ev);
                if is_first {
                    let mut sys_record = EVENT_RECORD::default();
                    sys_record.EventHeader.TimeStamp = (create_ts + 10_000) as i64;
                    assert!(handle_system_process_start(
                        &sys_record,
                        &aux_ctx,
                        Ok(StubSysProcSource {
                            pid: Some(6200),
                            parent_pid: Some(1200),
                            image_file_name: Some("cmd.exe".to_string()),
                            command_line: Some("cmd.exe /c during-dispatch".to_string()),
                        })
                    )
                    .is_none());
                }
                true
            });

            let main_ctx = EtwCallbackContext {
                sink: main_sink,
                dns_cache: Mutex::new(DnsResolutionCache::default()),
                volume_map: DosVolumeMap::with_mappings(Vec::new()),
                canary_matcher: Arc::new(RwLock::new(CanaryMatcher::default())),
                honeypot_handles: Mutex::new(HoneypotHandleTracker::default()),
                has_honeypot_handles: AtomicBool::new(false),
                registry_kcb_names: Mutex::new(HashMap::new()),
                cmdline_correlator: Arc::clone(&correlator),
                aux_active,
                stop_requested,
                session_name_nul: vec![0],
            };

            let initial = SensorEvent::ProcessStart {
                identity: ProcessIdentity::new(6200, create_ts),
                parent_pid: 1200,
                exe_path: r"C:\Windows\System32\cmd.exe".to_string(),
                command_line: String::new(),
                user_sid: None,
            };
            dispatch_process_start_with_correlator(&main_ctx, initial);

            let events = captured.lock().unwrap_or_else(|e| e.into_inner());
            assert_eq!(events.len(), 2);
            match (&events[0], &events[1]) {
                (
                    SensorEvent::ProcessStart { command_line: c0, .. },
                    SensorEvent::ProcessStart { command_line: c1, .. },
                ) => {
                    assert!(c0.is_empty(), "initial event must arrive before enriched");
                    assert_eq!(c1, "cmd.exe /c during-dispatch");
                }
                other => panic!("expected initial then enriched ProcessStart, got {other:?}"),
            }
            let corr = correlator.lock().unwrap_or_else(|e| e.into_inner());
            assert_eq!(corr.cached_sys_len(), 0);
            assert_eq!(corr.pending_starts_len(), 0);
        }
    }

    /// `ETW-P4-CMD-07` (correlator gate): When `aux_active == false` (auxiliary session startup
    /// failed or exited), `dispatch_process_start_with_correlator` does not accumulate
    /// `PendingKernelStart` entries while PEB fallback remains intact.
    #[test]
    fn etw_p4_cmd_07_aux_inactive_skips_pending_registration() {
        let (main_ctx, _aux_ctx, captured) = make_capturing_contexts(false);
        let create_ts: u64 = 133_800_000_000_000_000;

        let mut kp_record = EVENT_RECORD::default();
        kp_record.EventHeader.TimeStamp = create_ts as i64;
        kp_record.EventHeader.EventDescriptor.Id = 1;
        let ev = build_process_start_event(
            &kp_record,
            &main_ctx,
            Ok(StubPropertySource {
                pid: Some(7100),
                parent_pid: Some(1200),
                create_time_100ns: Some(create_ts),
                image_name: Some(r"C:\Windows\System32\cmd.exe".to_string()),
                command_line: None,
            }),
            |_| None,
        )
        .expect("ProcessStart emitted even when aux_active is false");
        dispatch_process_start_with_correlator(&main_ctx, ev);

        assert_eq!(
            captured
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len(),
            1
        );
        assert_eq!(
            main_ctx
                .cmdline_correlator
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .pending_starts_len(),
            0
        );
    }

    #[test]
    fn sens_fu_p4_03_process_start_collects_independent_package_attrs_across_paths() {
        let ctx = dummy_etw_ctx();
        let create_ts: u64 = 133_800_000_000_000_000;
        let mut record = EVENT_RECORD::default();
        record.EventHeader.TimeStamp = create_ts as i64;
        record.EventHeader.EventDescriptor.Id = 1;

        // 1. needs_inspect == true: both PFN and SID populated.
        let (_, pkg_both) = build_process_start_event_with_package(
            &record,
            &ctx,
            Ok(StubPropertySource {
                pid: Some(8101),
                parent_pid: Some(1200),
                create_time_100ns: Some(create_ts),
                image_name: Some(r"C:\Windows\System32\backgroundTaskHost.exe".to_string()),
                command_line: None,
            }),
            |_| {
                Some(ProcessInspectInfo {
                    parent_pid: Some(1200),
                    create_time_100ns: create_ts,
                    exe_path: Some(r"C:\Windows\System32\backgroundTaskHost.exe".to_string()),
                    command_line: Some("backgroundTaskHost.exe -ServerName:App".to_string()),
                    package_family_name: Some("Contoso.App_12345".to_string()),
                    package_sid: Some("S-1-15-2-11-22-33".to_string()),
                })
            },
            |_, _, _| panic!("inspect_package_fn must not run when needs_inspect is true"),
        )
        .expect("ProcessStart emitted");
        assert_eq!(
            pkg_both,
            ProcessPackageInfo {
                package_family_name: Some("Contoso.App_12345".to_string()),
                package_sid: Some("S-1-15-2-11-22-33".to_string()),
            }
        );

        // 2. needs_inspect == true: PFN_ONLY_NON_APPCONTAINER stays package_sid == None (no derivation).
        let (_, pkg_pfn_only) = build_process_start_event_with_package(
            &record,
            &ctx,
            Ok(StubPropertySource {
                pid: Some(8102),
                parent_pid: Some(1200),
                create_time_100ns: Some(create_ts),
                image_name: Some(r"C:\Windows\System32\RuntimeBroker.exe".to_string()),
                command_line: None,
            }),
            |_| {
                Some(ProcessInspectInfo {
                    parent_pid: Some(1200),
                    create_time_100ns: create_ts,
                    exe_path: Some(r"C:\Windows\System32\RuntimeBroker.exe".to_string()),
                    command_line: Some("RuntimeBroker.exe".to_string()),
                    package_family_name: Some("Microsoft.Windows.Shell_cw5n1h2txyewy".to_string()),
                    package_sid: None,
                })
            },
            |_, _, _| None,
        )
        .expect("ProcessStart emitted");
        assert_eq!(
            pkg_pfn_only.package_family_name.as_deref(),
            Some("Microsoft.Windows.Shell_cw5n1h2txyewy")
        );
        assert_eq!(pkg_pfn_only.package_sid, None);

        // 3. needs_inspect == false: inspect_package_fn supplies TOKEN_SID_ONLY.
        let (_, pkg_sid_only) = build_process_start_event_with_package(
            &record,
            &ctx,
            Ok(StubPropertySource {
                pid: Some(8103),
                parent_pid: Some(1200),
                create_time_100ns: Some(create_ts),
                image_name: Some(r"C:\Windows\System32\fontdrvhost.exe".to_string()),
                command_line: Some("fontdrvhost.exe".to_string()),
            }),
            |_| panic!("inspect_fn must not run when ETW supplies all 4 basic fields"),
            |pid, ct, _| {
                assert_eq!(pid, 8103);
                assert_eq!(ct, create_ts);
                Some(ProcessPackageInfo {
                    package_family_name: None,
                    package_sid: Some("S-1-15-2-99".to_string()),
                })
            },
        )
        .expect("ProcessStart emitted");
        assert_eq!(pkg_sid_only.package_family_name, None);
        assert_eq!(pkg_sid_only.package_sid.as_deref(), Some("S-1-15-2-99"));

        // 4. Mismatched incarnation (PID reuse) must drop inspected package attributes too.
        let (_, pkg_reused) = build_process_start_event_with_package(
            &record,
            &ctx,
            Ok(StubPropertySource {
                pid: Some(8104),
                parent_pid: Some(1200),
                create_time_100ns: Some(create_ts),
                image_name: Some(r"C:\Tools\app.exe".to_string()),
                command_line: None,
            }),
            |_| {
                Some(ProcessInspectInfo {
                    parent_pid: Some(1200),
                    create_time_100ns: create_ts + 999_999,
                    exe_path: Some(r"C:\Tools\other.exe".to_string()),
                    command_line: Some("other.exe".to_string()),
                    package_family_name: Some("Other.Pkg_1".to_string()),
                    package_sid: Some("S-1-15-2-77".to_string()),
                })
            },
            |_, _, _| None,
        )
        .expect("ProcessStart emitted");
        assert_eq!(pkg_reused, ProcessPackageInfo::default());
    }
}
