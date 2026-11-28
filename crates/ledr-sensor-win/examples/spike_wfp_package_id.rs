//! FU-P4-03 Pre-Implementation API Spike:
//! - AppContainer / Package Family Name -> `DeriveAppContainerSidFromAppContainerName` vs `TokenAppContainerSid`
//! - BFE `FWPM_CONDITION_ALE_PACKAGE_ID` (`FWP_SID`) filter acceptance & `FwpmNetEventSubscribe1/2` `packageSid`
//! - Self-contained AppContainer `curl.exe` Permit/Block isolation & drop-event `packageSid` verification
//!
//! Usage:
//!   cargo run -p ledr-sensor-win --example spike_wfp_package_id -- --probe-processes
//!   cargo run -p ledr-sensor-win --example spike_wfp_package_id -- --probe-processes --probe-wfp --wait-secs 20
//!   cargo run -p ledr-sensor-win --example spike_wfp_package_id -- --self-test-wfp

use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    APPMODEL_ERROR_NO_PACKAGE, CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, HANDLE,
    WAIT_OBJECT_0,
};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_ACTION0, FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_ALE_PACKAGE_ID, FWPM_DISPLAY_DATA0,
    FWPM_ENGINE_COLLECT_NET_EVENTS, FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_NONE,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_NET_EVENT2,
    FWPM_NET_EVENT3, FWPM_NET_EVENT_FLAG_PACKAGE_ID_SET, FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET,
    FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET, FWPM_NET_EVENT_SUBSCRIPTION0,
    FWPM_NET_EVENT_TYPE_CLASSIFY_DROP, FWPM_PROVIDER0, FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC,
    FWPM_SUBLAYER0, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE,
    FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_IP_VERSION_V4, FWP_IP_VERSION_V6,
    FWP_MATCH_EQUAL, FWP_SID, FWP_UINT32, FWP_UINT8, FWP_VALUE0, FWP_VALUE0_0, FwpmEngineClose0,
    FwpmEngineGetOption0, FwpmEngineOpen0, FwpmEngineSetOption0, FwpmFilterAdd0,
    FwpmFilterDeleteById0, FwpmFreeMemory0, FwpmGetAppIdFromFileName0, FwpmNetEventSubscribe1,
    FwpmNetEventSubscribe2, FwpmNetEventUnsubscribe0, FwpmProviderAdd0, FwpmProviderDeleteByKey0,
    FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0, FwpmTransactionAbort0, FwpmTransactionBegin0,
    FwpmTransactionCommit0,
};
use windows::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows::Win32::Security::{
    FreeSid, GetTokenInformation, PSID, SECURITY_CAPABILITIES, SID, SID_AND_ATTRIBUTES,
    TOKEN_APPCONTAINER_INFORMATION, TOKEN_QUERY, TokenAppContainerSid,
};
use windows::Win32::Storage::Packaging::Appx::GetPackageFamilyName;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
    GetExitCodeProcess, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    OpenProcess, OpenProcessToken, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    STARTUPINFOEXW, STARTUPINFOW, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
};

const ERROR_SUCCESS_U32: u32 = 0;
const SE_GROUP_ENABLED_U32: u32 = 0x0000_0004;
const INTERNET_CLIENT_CAPABILITY_SID: &str = "S-1-15-3-1";

// Dedicated spike GUIDs so we never collide with production LocalEDR GUIDs.
const SPIKE_PROVIDER_GUID: GUID = GUID::from_u128(0x9f1a_6420_3b7c_4a11_8b1e_0000_0000_0101);
const SPIKE_SUBLAYER_GUID: GUID = GUID::from_u128(0x9f1a_6420_3b7c_4a11_8b1e_0000_0000_0102);

#[link(name = "advapi32")]
unsafe extern "system" {
    fn ConvertSidToStringSidW(sid: *const c_void, string_sid: *mut *mut u16) -> i32;
    fn ConvertStringSidToSidW(string_sid: *const u16, sid: *mut *mut c_void) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LocalFree(hmem: *mut c_void) -> *mut c_void;
}

struct SpikeConfig {
    probe_processes: bool,
    probe_wfp: bool,
    self_test_wfp: bool,
    wait_secs: u64,
    target_exe: String,
    permit_pfn: String,
    block_pfn: String,
    self_test_url: String,
}

impl Default for SpikeConfig {
    fn default() -> Self {
        Self {
            probe_processes: false,
            probe_wfp: false,
            self_test_wfp: false,
            wait_secs: 0,
            target_exe: r"C:\Windows\System32\backgroundTaskHost.exe".to_string(),
            permit_pfn: "Microsoft.StartExperiencesApp_8wekyb3d8bbwe".to_string(),
            block_pfn: "Microsoft.WindowsStore_8wekyb3d8bbwe".to_string(),
            self_test_url: "http://1.1.1.1/".to_string(),
        }
    }
}

fn parse_args() -> Result<Option<SpikeConfig>, String> {
    let mut cfg = SpikeConfig::default();
    let mut args = std::env::args().skip(1);
    let mut any_mode = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print_usage();
                return Ok(None);
            }
            "--probe-processes" => {
                cfg.probe_processes = true;
                any_mode = true;
            }
            "--probe-wfp" => {
                cfg.probe_wfp = true;
                any_mode = true;
            }
            "--self-test-wfp" => {
                cfg.self_test_wfp = true;
                any_mode = true;
            }
            "--wait-secs" => {
                let raw = args
                    .next()
                    .ok_or_else(|| "--wait-secs requires an integer argument".to_string())?;
                cfg.wait_secs = raw
                    .parse::<u64>()
                    .map_err(|e| format!("invalid --wait-secs `{raw}`: {e}"))?;
            }
            "--target-exe" => {
                cfg.target_exe = args
                    .next()
                    .ok_or_else(|| "--target-exe requires a path argument".to_string())?;
            }
            "--permit-pfn" => {
                cfg.permit_pfn = args
                    .next()
                    .ok_or_else(|| "--permit-pfn requires a Package Family Name".to_string())?;
            }
            "--block-pfn" => {
                cfg.block_pfn = args
                    .next()
                    .ok_or_else(|| "--block-pfn requires a Package Family Name".to_string())?;
            }
            "--self-test-url" => {
                cfg.self_test_url = args
                    .next()
                    .ok_or_else(|| "--self-test-url requires a URL argument".to_string())?;
            }
            other => {
                return Err(format!("unknown argument `{other}` (use --help)"));
            }
        }
    }

    if !any_mode {
        print_usage();
        cfg.probe_processes = true;
    }

    Ok(Some(cfg))
}

fn print_usage() {
    println!(
        "FU-P4-03 spike_wfp_package_id\n\
         Options:\n\
         \x20 --probe-processes       Derive known PFN SIDs and inspect live Store processes\n\
         \x20 --probe-wfp             Register dynamic WFP APP_ID+PACKAGE_ID filters (requires admin)\n\
         \x20 --self-test-wfp         Run curl.exe in 2 temp AppContainers to verify isolation & net-events (admin)\n\
         \x20 --self-test-url <url>   Target URL for --self-test-wfp (default: http://1.1.1.1/)\n\
         \x20 --wait-secs <N>         Subscribe to FwpmNetEventSubscribe1/2 for N seconds (default: 0)\n\
         \x20 --target-exe <path>     Host exe path (default: C:\\Windows\\System32\\backgroundTaskHost.exe)\n\
         \x20 --permit-pfn <pfn>      PFN for Permit filter (default: Microsoft.StartExperiencesApp_8wekyb3d8bbwe)\n\
         \x20 --block-pfn <pfn>       PFN for Block filter (default: Microsoft.WindowsStore_8wekyb3d8bbwe)\n"
    );
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() && !self.0.0.is_null() {
            // SAFETY: `self.0` is an owned Win32 HANDLE closed once on drop.
            unsafe {
                let _ = CloseHandle(self.0);
            }
            self.0 = HANDLE::default();
        }
    }
}

struct OwnedFreeSid(PSID);

impl Drop for OwnedFreeSid {
    fn drop(&mut self) {
        if !self.0.is_invalid() && !self.0.0.is_null() {
            // SAFETY: `self.0` was allocated by `DeriveAppContainerSidFromAppContainerName` or
            // `CreateAppContainerProfile` and is freed with `FreeSid`.
            unsafe {
                let _ = FreeSid(self.0);
            }
            self.0 = PSID::default();
        }
    }
}

struct OwnedLocalPtr(*mut c_void);

impl Drop for OwnedLocalPtr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was allocated by `ConvertSidToStringSidW` or `ConvertStringSidToSidW`.
            unsafe {
                let _ = LocalFree(self.0);
            }
            self.0 = ptr::null_mut();
        }
    }
}

struct OwnedFwpByteBlob(*mut FWP_BYTE_BLOB);

impl OwnedFwpByteBlob {
    fn from_exe_path(exe_path: &str) -> Result<Self, String> {
        let wide = encode_wide_nul(exe_path);
        let mut blob_ptr: *mut FWP_BYTE_BLOB = ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated UTF-16 and `blob_ptr` receives a BFE-allocated blob.
        let status = unsafe { FwpmGetAppIdFromFileName0(PCWSTR(wide.as_ptr()), &mut blob_ptr) };
        if status != ERROR_SUCCESS_U32 || blob_ptr.is_null() {
            return Err(format!(
                "FwpmGetAppIdFromFileName0(`{exe_path}`) failed: 0x{status:08X}"
            ));
        }
        Ok(Self(blob_ptr))
    }
}

impl Drop for OwnedFwpByteBlob {
    fn drop(&mut self) {
        if !self.0.is_null() {
            let mut raw = self.0.cast::<c_void>();
            // SAFETY: `self.0` was allocated by `FwpmGetAppIdFromFileName0` and is freed via `FwpmFreeMemory0`.
            unsafe { FwpmFreeMemory0(&mut raw) };
            self.0 = ptr::null_mut();
        }
    }
}

struct OwnedWfpEngine(HANDLE);

impl Drop for OwnedWfpEngine {
    fn drop(&mut self) {
        if !self.0.is_invalid() && !self.0.0.is_null() {
            // SAFETY: `self.0` was opened via `FwpmEngineOpen0` with `FWPM_SESSION_FLAG_DYNAMIC`.
            let _ = unsafe { FwpmEngineClose0(self.0) };
            self.0 = HANDLE::default();
        }
    }
}

struct OwnedProcThreadAttrList {
    _buf: Vec<u8>,
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
}

impl OwnedProcThreadAttrList {
    fn new(attr_count: u32) -> Result<Self, String> {
        let mut size: usize = 0;
        // SAFETY: probing required attribute-list size; `ERROR_INSUFFICIENT_BUFFER` is expected.
        let _ = unsafe { InitializeProcThreadAttributeList(None, attr_count, None, &mut size) };
        if size == 0 {
            return Err("InitializeProcThreadAttributeList returned size 0".to_string());
        }
        let mut buf = vec![0u8; size];
        let list = LPPROC_THREAD_ATTRIBUTE_LIST(buf.as_mut_ptr().cast::<c_void>());
        // SAFETY: `buf` is `size` bytes and stays pinned inside `Self` until `DeleteProcThreadAttributeList`.
        unsafe { InitializeProcThreadAttributeList(Some(list), attr_count, None, &mut size) }
            .map_err(|e| format!("InitializeProcThreadAttributeList failed: {e}"))?;
        Ok(Self { _buf: buf, list })
    }
}

impl Drop for OwnedProcThreadAttrList {
    fn drop(&mut self) {
        if !self.list.is_invalid() {
            // SAFETY: `self.list` was initialized by `InitializeProcThreadAttributeList`.
            unsafe { DeleteProcThreadAttributeList(self.list) };
            self.list = LPPROC_THREAD_ATTRIBUTE_LIST::default();
        }
    }
}

struct OwnedAppContainerProfile {
    name: String,
    sid: OwnedFreeSid,
    sid_str: String,
}

impl OwnedAppContainerProfile {
    fn create_fresh(name: &str, caps: &[SID_AND_ATTRIBUTES]) -> Result<Self, String> {
        let name_w = encode_wide_nul(name);
        // Clean up any leftover profile from an interrupted prior run.
        // SAFETY: `name_w` is a valid NUL-terminated UTF-16 profile name.
        let _ = unsafe { DeleteAppContainerProfile(PCWSTR(name_w.as_ptr())) };
        // SAFETY: `name_w` and `caps` remain valid for `CreateAppContainerProfile`.
        let psid = unsafe {
            CreateAppContainerProfile(
                PCWSTR(name_w.as_ptr()),
                PCWSTR(name_w.as_ptr()),
                PCWSTR(name_w.as_ptr()),
                Some(caps),
            )
        }
        .map_err(|e| format!("CreateAppContainerProfile(`{name}`) failed: {e}"))?;
        let sid = OwnedFreeSid(psid);
        let sid_str = sid_ptr_to_string(sid.0.0)?;
        Ok(Self {
            name: name.to_string(),
            sid,
            sid_str,
        })
    }
}

impl Drop for OwnedAppContainerProfile {
    fn drop(&mut self) {
        let name_w = encode_wide_nul(&self.name);
        // SAFETY: `name_w` is NUL-terminated UTF-16; deletes temporary profile on exit.
        let _ = unsafe { DeleteAppContainerProfile(PCWSTR(name_w.as_ptr())) };
    }
}

fn encode_wide_nul(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_slice_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

fn sid_ptr_to_string(sid: *const c_void) -> Result<String, String> {
    if sid.is_null() {
        return Err("null SID pointer".to_string());
    }
    let mut ptr_wide: *mut u16 = ptr::null_mut();
    // SAFETY: `sid` is a valid non-null Win32 SID pointer for the duration of this call.
    let ok = unsafe { ConvertSidToStringSidW(sid, &mut ptr_wide) };
    if ok == 0 || ptr_wide.is_null() {
        return Err(format!(
            "ConvertSidToStringSidW failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let _guard = OwnedLocalPtr(ptr_wide.cast::<c_void>());
    let mut len = 0usize;
    // SAFETY: `ConvertSidToStringSidW` guarantees a NUL-terminated UTF-16 string.
    while unsafe { *ptr_wide.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `ptr_wide` points to `len` valid `u16` code units.
    let slice = unsafe { std::slice::from_raw_parts(ptr_wide, len) };
    Ok(String::from_utf16_lossy(slice))
}

fn string_to_local_sid(sid_str: &str) -> Result<OwnedLocalPtr, String> {
    let wide = encode_wide_nul(sid_str);
    let mut raw_sid: *mut c_void = ptr::null_mut();
    // SAFETY: `wide` is NUL-terminated UTF-16; `raw_sid` is freed via `LocalFree` in `OwnedLocalPtr`.
    let ok = unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut raw_sid) };
    if ok == 0 || raw_sid.is_null() {
        return Err(format!(
            "ConvertStringSidToSidW(`{sid_str}`) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(OwnedLocalPtr(raw_sid))
}

fn derive_sid_for_pfn(pfn: &str) -> Result<(OwnedFreeSid, String), String> {
    let wide = encode_wide_nul(pfn);
    // SAFETY: `wide` is a valid NUL-terminated UTF-16 string.
    let psid = unsafe { DeriveAppContainerSidFromAppContainerName(PCWSTR(wide.as_ptr())) }
        .map_err(|e| format!("DeriveAppContainerSidFromAppContainerName(`{pfn}`) failed: {e}"))?;
    let owned = OwnedFreeSid(psid);
    let sid_str = sid_ptr_to_string(owned.0.0)?;
    Ok((owned, sid_str))
}

fn query_process_package_family_name(proc_handle: HANDLE) -> Result<Option<String>, String> {
    let mut len: u32 = 0;
    // SAFETY: `proc_handle` is a valid process handle; `None` queries required UTF-16 buffer length.
    let first = unsafe { GetPackageFamilyName(proc_handle, &mut len, None) };
    if first == APPMODEL_ERROR_NO_PACKAGE {
        return Ok(None);
    }
    if first != ERROR_INSUFFICIENT_BUFFER {
        return Err(format!("GetPackageFamilyName(size) failed: {}", first.0));
    }
    let mut buf = vec![0u16; len as usize];
    // SAFETY: `buf` has length `len` as requested by `GetPackageFamilyName`.
    let second = unsafe {
        GetPackageFamilyName(proc_handle, &mut len, Some(PWSTR(buf.as_mut_ptr())))
    };
    if second == APPMODEL_ERROR_NO_PACKAGE {
        return Ok(None);
    }
    if second != ERROR_SUCCESS {
        return Err(format!("GetPackageFamilyName(read) failed: {}", second.0));
    }
    Ok(Some(wide_slice_to_string(&buf)))
}

fn query_token_app_container_sid(proc_handle: HANDLE) -> Result<Option<String>, String> {
    let mut token = HANDLE::default();
    // SAFETY: `proc_handle` is valid; `token` receives the opened token handle.
    unsafe { OpenProcessToken(proc_handle, TOKEN_QUERY, &mut token) }
        .map_err(|e| format!("OpenProcessToken failed: {e}"))?;
    let _token_guard = OwnedHandle(token);

    let mut needed: u32 = 0;
    // SAFETY: probing required buffer size for `TokenAppContainerSid`.
    let first = unsafe { GetTokenInformation(token, TokenAppContainerSid, None, 0, &mut needed) };
    if first.is_ok() {
        return Ok(None);
    }
    let last_err = std::io::Error::last_os_error();
    if last_err.raw_os_error() != Some(i32::try_from(ERROR_INSUFFICIENT_BUFFER.0).unwrap_or(122)) {
        return Err(format!(
            "GetTokenInformation(TokenAppContainerSid, size) failed: {last_err}"
        ));
    }

    let mut buf = vec![0u8; needed as usize];
    // SAFETY: `buf` has `needed` bytes and `TOKEN_APPCONTAINER_INFORMATION` lives at offset 0.
    unsafe {
        GetTokenInformation(
            token,
            TokenAppContainerSid,
            Some(buf.as_mut_ptr().cast::<c_void>()),
            needed,
            &mut needed,
        )
    }
    .map_err(|e| format!("GetTokenInformation(TokenAppContainerSid, read) failed: {e}"))?;

    if buf.len() < std::mem::size_of::<TOKEN_APPCONTAINER_INFORMATION>() {
        return Err("TokenAppContainerSid buffer smaller than header".to_string());
    }
    // SAFETY: `buf` is at least `size_of::<TOKEN_APPCONTAINER_INFORMATION>()` bytes; read_unaligned avoids alignment UB.
    let info = unsafe { ptr::read_unaligned(buf.as_ptr().cast::<TOKEN_APPCONTAINER_INFORMATION>()) };
    if info.TokenAppContainer.is_invalid() || info.TokenAppContainer.0.is_null() {
        return Ok(None);
    }
    let sid_str = sid_ptr_to_string(info.TokenAppContainer.0)?;
    Ok(Some(sid_str))
}

fn run_probe_processes(cfg: &SpikeConfig) -> Result<(), String> {
    println!("=== Known PFN Derivation Check ===");
    let known_pfns = [
        cfg.permit_pfn.as_str(),
        cfg.block_pfn.as_str(),
        "Microsoft.WindowsCalculator_8wekyb3d8bbwe",
    ];
    for pfn in known_pfns {
        let (_sid, sid_str) = derive_sid_for_pfn(pfn)?;
        println!("  PFN `{pfn}` -> SID `{sid_str}`");
    }

    println!("\n=== Live Process AppContainer / PFN Probe ===");
    // SAFETY: `TH32CS_SNAPPROCESS` with pid 0 snapshots all processes.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(|e| format!("CreateToolhelp32Snapshot failed: {e}"))?;
    let _snap_guard = OwnedHandle(snap);

    let mut entry = PROCESSENTRY32W {
        dwSize: u32::try_from(std::mem::size_of::<PROCESSENTRY32W>()).unwrap_or(0),
        ..Default::default()
    };

    // SAFETY: `entry.dwSize` is initialized before calling `Process32FirstW`.
    if unsafe { Process32FirstW(snap, &mut entry) }.is_err() {
        return Err("Process32FirstW failed".to_string());
    }

    let mut total_procs = 0usize;
    let mut open_denied = 0usize;
    let mut packaged_count = 0usize;
    let mut appcontainer_count = 0usize;
    let mut both_matched = 0usize;
    let mut mismatched = 0usize;
    let mut query_errors = 0usize;
    let mut bth_seen = 0usize;

    loop {
        total_procs += 1;
        let pid = entry.th32ProcessID;
        let exe_name = wide_slice_to_string(&entry.szExeFile);
        let is_bth = exe_name.eq_ignore_ascii_case("backgroundTaskHost.exe");
        if is_bth {
            bth_seen += 1;
        }

        if pid != 0 {
            // SAFETY: opening process with `PROCESS_QUERY_LIMITED_INFORMATION` only.
            match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
                Ok(proc_h) => {
                    let _proc_guard = OwnedHandle(proc_h);
                    let pfn_res = query_process_package_family_name(proc_h);
                    let token_res = query_token_app_container_sid(proc_h);
                    let derived_res = match &pfn_res {
                        Ok(Some(name)) => Some(derive_sid_for_pfn(name).map(|(_, s)| s)),
                        _ => None,
                    };

                    if let Ok(Some(_)) = &pfn_res {
                        packaged_count += 1;
                    }
                    if let Ok(Some(_)) = &token_res {
                        appcontainer_count += 1;
                    }

                    let has_error = pfn_res.is_err()
                        || token_res.is_err()
                        || matches!(derived_res, Some(Err(_)));
                    let has_data = matches!(pfn_res, Ok(Some(_)))
                        || matches!(token_res, Ok(Some(_)));

                    if has_error {
                        query_errors += 1;
                        let pfn_disp = match &pfn_res {
                            Ok(Some(v)) => v.as_str(),
                            Ok(None) => "-",
                            Err(_) => "<ERR>",
                        };
                        let derived_disp = match &derived_res {
                            Some(Ok(v)) => v.as_str(),
                            Some(Err(_)) => "<ERR>",
                            None => "-",
                        };
                        let token_disp = match &token_res {
                            Ok(Some(v)) => v.as_str(),
                            Ok(None) => "-",
                            Err(_) => "<ERR>",
                        };
                        let mut err_parts = Vec::new();
                        if let Err(e) = &pfn_res {
                            err_parts.push(format!("pfn:{e}"));
                        }
                        if let Err(e) = &token_res {
                            err_parts.push(format!("token:{e}"));
                        }
                        if let Some(Err(e)) = &derived_res {
                            err_parts.push(format!("derive:{e}"));
                        }
                        println!(
                            "  pid={pid:<6} exe={exe_name:<28} status=QUERY_ERROR              pfn={pfn_disp} derived={derived_disp} token={token_disp} errors=[{}]",
                            err_parts.join("; ")
                        );
                    } else if has_data || is_bth {
                        let pfn = pfn_res.ok().flatten();
                        let token_sid = token_res.ok().flatten();
                        let derived_sid = derived_res.and_then(Result::ok);
                        let status_tag = match (&derived_sid, &token_sid) {
                            (Some(d), Some(t)) if d == t => {
                                both_matched += 1;
                                "MATCH"
                            }
                            (Some(_), Some(_)) => {
                                mismatched += 1;
                                "MISMATCH"
                            }
                            (Some(_), None) => "PFN_ONLY_NON_APPCONTAINER",
                            (None, Some(_)) => "TOKEN_SID_ONLY",
                            (None, None) => "NON_PACKAGED",
                        };
                        println!(
                            "  pid={pid:<6} exe={exe_name:<28} status={status_tag:<24} pfn={} derived={} token={}",
                            pfn.as_deref().unwrap_or("-"),
                            derived_sid.as_deref().unwrap_or("-"),
                            token_sid.as_deref().unwrap_or("-")
                        );
                    }
                }
                Err(_) => {
                    open_denied += 1;
                }
            }
        }

        // SAFETY: `entry.dwSize` remains valid across `Process32NextW`.
        if unsafe { Process32NextW(snap, &mut entry) }.is_err() {
            break;
        }
    }

    println!(
        "\nSummary: total={total_procs}, open_denied={open_denied}, query_errors={query_errors}, backgroundTaskHost_seen={bth_seen}, packaged={packaged_count}, appcontainer={appcontainer_count}, sid_match={both_matched}, sid_mismatch={mismatched}"
    );
    if mismatched > 0 {
        return Err(format!("detected {mismatched} SID mismatch(es)"));
    }
    Ok(())
}

#[derive(Debug)]
struct ObservedNetEvent {
    api_version: &'static str,
    filter_id: u64,
    flag_package_id_set: bool,
    package_sid: Option<String>,
    dst_ip: Option<IpAddr>,
    dst_port: u16,
}

struct NetEventCtx {
    api_version: &'static str,
    active: AtomicBool,
    events: Arc<Mutex<Vec<ObservedNetEvent>>>,
}

fn parse_header_common(
    flags: u32,
    dst_ip: Option<IpAddr>,
    remote_port: u16,
    package_sid_ptr: *const SID,
) -> (bool, Option<String>, Option<IpAddr>, u16) {
    let flag_pkg = (flags & FWPM_NET_EVENT_FLAG_PACKAGE_ID_SET) != 0;
    let pkg_sid = if package_sid_ptr.is_null() {
        None
    } else {
        sid_ptr_to_string(package_sid_ptr.cast::<c_void>()).ok()
    };
    let dst_port = if (flags & FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET) != 0 {
        remote_port
    } else {
        0
    };
    (flag_pkg, pkg_sid, dst_ip, dst_port)
}

unsafe extern "system" fn spike_net_event_cb1(
    context: *mut c_void,
    event: *const FWPM_NET_EVENT2,
) {
    if context.is_null() || event.is_null() {
        return;
    }
    // SAFETY: `context` points to a live `NetEventCtx` until `FwpmNetEventUnsubscribe0` succeeds.
    let ctx = unsafe { &*(context as *const NetEventCtx) };
    if !ctx.active.load(Ordering::Acquire) {
        return;
    }
    // SAFETY: `event` is a valid BFE `FWPM_NET_EVENT2` pointer for the callback duration.
    let ev = unsafe { &*event };
    if ev.r#type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP {
        return;
    }
    // SAFETY: `ev.r#type == FWPM_NET_EVENT_TYPE_CLASSIFY_DROP` selects `classifyDrop`.
    let drop_ptr = unsafe { ev.Anonymous.classifyDrop };
    if drop_ptr.is_null() {
        return;
    }
    // SAFETY: `drop_ptr` is non-null when `classifyDrop` is present.
    let drop_info = unsafe { &*drop_ptr };
    let dst_ip = if (ev.header.flags & FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET) != 0 {
        match ev.header.ipVersion {
            // SAFETY: `ipVersion == FWP_IP_VERSION_V4` selects `remoteAddrV4`.
            FWP_IP_VERSION_V4 => Some(IpAddr::V4(Ipv4Addr::from(unsafe {
                ev.header.Anonymous2.remoteAddrV4
            }))),
            // SAFETY: `ipVersion == FWP_IP_VERSION_V6` selects `remoteAddrV6`.
            FWP_IP_VERSION_V6 => Some(IpAddr::V6(Ipv6Addr::from(unsafe {
                ev.header.Anonymous2.remoteAddrV6.byteArray16
            }))),
            _ => None,
        }
    } else {
        None
    };
    let (flag_pkg, pkg_sid, dst_ip, dst_port) = parse_header_common(
        ev.header.flags,
        dst_ip,
        ev.header.remotePort,
        ev.header.packageSid,
    );
    if let Ok(mut guard) = ctx.events.try_lock() {
        guard.push(ObservedNetEvent {
            api_version: ctx.api_version,
            filter_id: drop_info.filterId,
            flag_package_id_set: flag_pkg,
            package_sid: pkg_sid,
            dst_ip,
            dst_port,
        });
    }
}

unsafe extern "system" fn spike_net_event_cb2(
    context: *mut c_void,
    event: *const FWPM_NET_EVENT3,
) {
    if context.is_null() || event.is_null() {
        return;
    }
    // SAFETY: `context` points to a live `NetEventCtx` until `FwpmNetEventUnsubscribe0` succeeds.
    let ctx = unsafe { &*(context as *const NetEventCtx) };
    if !ctx.active.load(Ordering::Acquire) {
        return;
    }
    // SAFETY: `event` is a valid BFE `FWPM_NET_EVENT3` pointer for the callback duration.
    let ev = unsafe { &*event };
    if ev.r#type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP {
        return;
    }
    // SAFETY: `ev.r#type == FWPM_NET_EVENT_TYPE_CLASSIFY_DROP` selects `classifyDrop`.
    let drop_ptr = unsafe { ev.Anonymous.classifyDrop };
    if drop_ptr.is_null() {
        return;
    }
    // SAFETY: `drop_ptr` is non-null when `classifyDrop` is present.
    let drop_info = unsafe { &*drop_ptr };
    let dst_ip = if (ev.header.flags & FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET) != 0 {
        match ev.header.ipVersion {
            // SAFETY: `ipVersion == FWP_IP_VERSION_V4` selects `remoteAddrV4`.
            FWP_IP_VERSION_V4 => Some(IpAddr::V4(Ipv4Addr::from(unsafe {
                ev.header.Anonymous2.remoteAddrV4
            }))),
            // SAFETY: `ipVersion == FWP_IP_VERSION_V6` selects `remoteAddrV6`.
            FWP_IP_VERSION_V6 => Some(IpAddr::V6(Ipv6Addr::from(unsafe {
                ev.header.Anonymous2.remoteAddrV6.byteArray16
            }))),
            _ => None,
        }
    } else {
        None
    };
    let (flag_pkg, pkg_sid, dst_ip, dst_port) = parse_header_common(
        ev.header.flags,
        dst_ip,
        ev.header.remotePort,
        ev.header.packageSid,
    );
    if let Ok(mut guard) = ctx.events.try_lock() {
        guard.push(ObservedNetEvent {
            api_version: ctx.api_version,
            filter_id: drop_info.filterId,
            flag_package_id_set: flag_pkg,
            package_sid: pkg_sid,
            dst_ip,
            dst_port,
        });
    }
}

fn add_package_scoped_filter(
    engine: HANDLE,
    app_blob: &OwnedFwpByteBlob,
    package_sid: PSID,
    layer: GUID,
    layer_label: &str,
    allow: bool,
    weight: u8,
) -> Result<u64, String> {
    let mut conditions = [
        FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_APP_ID,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_BYTE_BLOB_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    byteBlob: app_blob.0,
                },
            },
        },
        FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_PACKAGE_ID,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_SID,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    sid: package_sid.0.cast::<SID>(),
                },
            },
        },
    ];

    let action_label = if allow { "Permit" } else { "Block" };
    let mut name_w = encode_wide_nul(&format!("LocalEDR Spike {action_label} ({layer_label})"));
    let mut desc_w = encode_wide_nul("FU-P4-03 dynamic ALE_APP_ID + ALE_PACKAGE_ID spike filter");
    let mut provider_guid = SPIKE_PROVIDER_GUID;
    let filter = FWPM_FILTER0 {
        displayData: FWPM_DISPLAY_DATA0 {
            name: PWSTR(name_w.as_mut_ptr()),
            description: PWSTR(desc_w.as_mut_ptr()),
        },
        flags: FWPM_FILTER_FLAG_NONE,
        providerKey: &mut provider_guid,
        layerKey: layer,
        subLayerKey: SPIKE_SUBLAYER_GUID,
        weight: FWP_VALUE0 {
            r#type: FWP_UINT8,
            Anonymous: FWP_VALUE0_0 { uint8: weight },
        },
        numFilterConditions: u32::try_from(conditions.len()).unwrap_or(0),
        filterCondition: conditions.as_mut_ptr(),
        action: FWPM_ACTION0 {
            r#type: if allow {
                FWP_ACTION_PERMIT
            } else {
                FWP_ACTION_BLOCK
            },
            ..Default::default()
        },
        ..Default::default()
    };

    let mut filter_id: u64 = 0;
    // SAFETY: `filter`, `conditions`, `app_blob`, `package_sid`, and display strings stay live during the call.
    let status = unsafe { FwpmFilterAdd0(engine, &filter, None, Some(&mut filter_id)) };
    if status != ERROR_SUCCESS_U32 {
        return Err(format!(
            "FwpmFilterAdd0({action_label}, {layer_label}) failed: 0x{status:08X}"
        ));
    }
    Ok(filter_id)
}

struct SubHandle {
    handle: HANDLE,
    ctx_ptr: *mut NetEventCtx,
}

struct SpikeWfpSession {
    engine: OwnedWfpEngine,
    permit_filter_ids: Vec<u64>,
    block_filter_ids: Vec<u64>,
    enabled_net_events_by_us: bool,
    sub1: Option<SubHandle>,
    sub2: Option<SubHandle>,
    events: Arc<Mutex<Vec<ObservedNetEvent>>>,
}

impl SpikeWfpSession {
    fn open_with_package_filters(
        target_exe: &str,
        permit_sid: PSID,
        block_sid: PSID,
    ) -> Result<Self, String> {
        let app_blob = OwnedFwpByteBlob::from_exe_path(target_exe)?;

        let mut session_name = encode_wide_nul("LocalEDR FU-P4-03 Spike Session");
        let mut session_desc =
            encode_wide_nul("Temporary dynamic WFP session for ALE_PACKAGE_ID spike");
        let session = FWPM_SESSION0 {
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(session_name.as_mut_ptr()),
                description: PWSTR(session_desc.as_mut_ptr()),
            },
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            ..Default::default()
        };

        let mut raw_engine = HANDLE::default();
        // SAFETY: `session` and its display strings remain live during `FwpmEngineOpen0`.
        let open_status = unsafe {
            FwpmEngineOpen0(
                PCWSTR::null(),
                RPC_C_AUTHN_WINNT,
                None,
                Some(&session),
                &mut raw_engine,
            )
        };
        if open_status != ERROR_SUCCESS_U32 || raw_engine.is_invalid() || raw_engine.0.is_null() {
            return Err(format!(
                "FwpmEngineOpen0(FWPM_SESSION_FLAG_DYNAMIC) failed: 0x{open_status:08X} (run in elevated Administrator PowerShell)"
            ));
        }
        let engine = OwnedWfpEngine(raw_engine);

        // SAFETY: `engine.0` is a valid open dynamic WFP session.
        let begin_status = unsafe { FwpmTransactionBegin0(engine.0, 0) };
        if begin_status != ERROR_SUCCESS_U32 {
            return Err(format!("FwpmTransactionBegin0 failed: 0x{begin_status:08X}"));
        }

        let mut permit_filter_ids = Vec::new();
        let mut block_filter_ids = Vec::new();
        let setup_res = (|| -> Result<(), String> {
            let mut prov_name = encode_wide_nul("LocalEDR Spike Provider");
            let mut prov_desc = encode_wide_nul("Temporary spike provider");
            let provider = FWPM_PROVIDER0 {
                providerKey: SPIKE_PROVIDER_GUID,
                displayData: FWPM_DISPLAY_DATA0 {
                    name: PWSTR(prov_name.as_mut_ptr()),
                    description: PWSTR(prov_desc.as_mut_ptr()),
                },
                flags: 0,
                ..Default::default()
            };
            // SAFETY: `provider` and its UTF-16 display strings remain valid during `FwpmProviderAdd0`.
            let st_prov = unsafe { FwpmProviderAdd0(engine.0, &provider, None) };
            if st_prov != ERROR_SUCCESS_U32 {
                return Err(format!("FwpmProviderAdd0 failed: 0x{st_prov:08X}"));
            }

            let mut sl_name = encode_wide_nul("LocalEDR Spike SubLayer");
            let mut sl_desc = encode_wide_nul("Temporary spike sublayer");
            let mut prov_guid = SPIKE_PROVIDER_GUID;
            let sublayer = FWPM_SUBLAYER0 {
                subLayerKey: SPIKE_SUBLAYER_GUID,
                displayData: FWPM_DISPLAY_DATA0 {
                    name: PWSTR(sl_name.as_mut_ptr()),
                    description: PWSTR(sl_desc.as_mut_ptr()),
                },
                flags: 0,
                providerKey: &mut prov_guid,
                weight: 0x7FFF,
                ..Default::default()
            };
            // SAFETY: `sublayer` and `prov_guid` remain valid during `FwpmSubLayerAdd0`.
            let st_sl = unsafe { FwpmSubLayerAdd0(engine.0, &sublayer, None) };
            if st_sl != ERROR_SUCCESS_U32 {
                return Err(format!("FwpmSubLayerAdd0 failed: 0x{st_sl:08X}"));
            }

            for (layer, label) in [
                (FWPM_LAYER_ALE_AUTH_CONNECT_V4, "v4"),
                (FWPM_LAYER_ALE_AUTH_CONNECT_V6, "v6"),
            ] {
                let permit_id = add_package_scoped_filter(
                    engine.0,
                    &app_blob,
                    permit_sid,
                    layer,
                    label,
                    true,
                    12,
                )?;
                println!("  [OK] Permit ({label}) filter_id={permit_id}");
                permit_filter_ids.push(permit_id);

                let block_id = add_package_scoped_filter(
                    engine.0,
                    &app_blob,
                    block_sid,
                    layer,
                    label,
                    false,
                    10,
                )?;
                println!("  [OK] Block  ({label}) filter_id={block_id}");
                block_filter_ids.push(block_id);
            }
            Ok(())
        })();

        if let Err(err) = setup_res {
            // SAFETY: aborting uncommitted WFP transaction on error.
            let _ = unsafe { FwpmTransactionAbort0(engine.0) };
            return Err(err);
        }

        // SAFETY: committing valid WFP transaction.
        let commit_status = unsafe { FwpmTransactionCommit0(engine.0) };
        if commit_status != ERROR_SUCCESS_U32 {
            // SAFETY: aborting transaction if commit failed.
            let _ = unsafe { FwpmTransactionAbort0(engine.0) };
            return Err(format!("FwpmTransactionCommit0 failed: 0x{commit_status:08X}"));
        }

        Ok(Self {
            engine,
            permit_filter_ids,
            block_filter_ids,
            enabled_net_events_by_us: false,
            sub1: None,
            sub2: None,
            events: Arc::new(Mutex::new(Vec::new())),
        })
    }

    fn subscribe_net_events(&mut self) -> Result<(), String> {
        let mut opt_ptr: *mut FWP_VALUE0 = ptr::null_mut();
        // SAFETY: `self.engine.0` is open; `opt_ptr` is freed via `FwpmFreeMemory0`.
        let get_status = unsafe {
            FwpmEngineGetOption0(
                self.engine.0,
                FWPM_ENGINE_COLLECT_NET_EVENTS,
                &mut opt_ptr,
            )
        };
        if get_status != ERROR_SUCCESS_U32 || opt_ptr.is_null() {
            return Err(format!(
                "FwpmEngineGetOption0(COLLECT_NET_EVENTS) failed: 0x{get_status:08X}"
            ));
        }
        // SAFETY: `opt_ptr` points to a valid `FWP_VALUE0` allocated by `FwpmEngineGetOption0`.
        let prev_collect = unsafe {
            let val = if (*opt_ptr).r#type == FWP_UINT32 {
                (*opt_ptr).Anonymous.uint32
            } else {
                0
            };
            let mut raw = opt_ptr.cast::<c_void>();
            FwpmFreeMemory0(&mut raw);
            val
        };

        if prev_collect == 0 {
            let enable = FWP_VALUE0 {
                r#type: FWP_UINT32,
                Anonymous: FWP_VALUE0_0 { uint32: 1 },
            };
            // SAFETY: `self.engine.0` is open and `enable` stays valid across `FwpmEngineSetOption0`.
            let set_st = unsafe {
                FwpmEngineSetOption0(self.engine.0, FWPM_ENGINE_COLLECT_NET_EVENTS, &enable)
            };
            if set_st != ERROR_SUCCESS_U32 {
                return Err(format!(
                    "FwpmEngineSetOption0(COLLECT_NET_EVENTS=1) failed: 0x{set_st:08X}"
                ));
            }
            self.enabled_net_events_by_us = true;
        }

        let sub_req = FWPM_NET_EVENT_SUBSCRIPTION0::default();

        let ctx1 = Box::into_raw(Box::new(NetEventCtx {
            api_version: "v1/HEADER2",
            active: AtomicBool::new(true),
            events: Arc::clone(&self.events),
        }));
        let mut handle1 = HANDLE::default();
        // SAFETY: `self.engine.0` is open, `sub_req` and `ctx1` stay valid until unsubscribe succeeds.
        let st1 = unsafe {
            FwpmNetEventSubscribe1(
                self.engine.0,
                &sub_req,
                Some(spike_net_event_cb1),
                Some(ctx1.cast::<c_void>()),
                &mut handle1,
            )
        };
        if st1 == ERROR_SUCCESS_U32 && !handle1.is_invalid() && !handle1.0.is_null() {
            self.sub1 = Some(SubHandle {
                handle: handle1,
                ctx_ptr: ctx1,
            });
        } else {
            // SAFETY: subscription failed so `ctx1` is not referenced by BFE.
            unsafe { drop(Box::from_raw(ctx1)) };
            println!("  [WARN] FwpmNetEventSubscribe1 failed: 0x{st1:08X}");
        }

        let ctx2 = Box::into_raw(Box::new(NetEventCtx {
            api_version: "v2/HEADER3",
            active: AtomicBool::new(true),
            events: Arc::clone(&self.events),
        }));
        let mut handle2 = HANDLE::default();
        // SAFETY: `self.engine.0` is open, `sub_req` and `ctx2` stay valid until unsubscribe succeeds.
        let st2 = unsafe {
            FwpmNetEventSubscribe2(
                self.engine.0,
                &sub_req,
                Some(spike_net_event_cb2),
                Some(ctx2.cast::<c_void>()),
                &mut handle2,
            )
        };
        if st2 == ERROR_SUCCESS_U32 && !handle2.is_invalid() && !handle2.0.is_null() {
            self.sub2 = Some(SubHandle {
                handle: handle2,
                ctx_ptr: ctx2,
            });
        } else {
            // SAFETY: subscription failed so `ctx2` is not referenced by BFE.
            unsafe { drop(Box::from_raw(ctx2)) };
            println!("  [WARN] FwpmNetEventSubscribe2 failed: 0x{st2:08X}");
        }

        Ok(())
    }

    fn unsubscribe_net_events(&mut self) {
        for slot in [&mut self.sub1, &mut self.sub2] {
            if let Some(sub) = slot.take() {
                // SAFETY: `sub.ctx_ptr` stays valid until `FwpmNetEventUnsubscribe0` succeeds.
                unsafe { (*sub.ctx_ptr).active.store(false, Ordering::Release) };
                // SAFETY: `self.engine.0` and `sub.handle` are valid handles.
                let unsub = unsafe { FwpmNetEventUnsubscribe0(self.engine.0, sub.handle) };
                if unsub == ERROR_SUCCESS_U32 {
                    // SAFETY: unsubscribe waited for in-flight callbacks; safe to reclaim `ctx_ptr`.
                    unsafe { drop(Box::from_raw(sub.ctx_ptr)) };
                } else {
                    *slot = Some(sub);
                }
            }
        }
        if self.enabled_net_events_by_us && self.sub1.is_none() && self.sub2.is_none() {
            let disable = FWP_VALUE0 {
                r#type: FWP_UINT32,
                Anonymous: FWP_VALUE0_0 { uint32: 0 },
            };
            // SAFETY: restoring previous `FWPM_ENGINE_COLLECT_NET_EVENTS=0` state.
            let _ = unsafe {
                FwpmEngineSetOption0(self.engine.0, FWPM_ENGINE_COLLECT_NET_EVENTS, &disable)
            };
            self.enabled_net_events_by_us = false;
        }
    }
}

impl Drop for SpikeWfpSession {
    fn drop(&mut self) {
        self.unsubscribe_net_events();
        // SAFETY: `self.engine.0` is open and filter/sublayer/provider IDs belong to this session.
        unsafe {
            for fid in self
                .permit_filter_ids
                .drain(..)
                .chain(self.block_filter_ids.drain(..))
            {
                let _ = FwpmFilterDeleteById0(self.engine.0, fid);
            }
            let _ = FwpmSubLayerDeleteByKey0(self.engine.0, &SPIKE_SUBLAYER_GUID);
            let _ = FwpmProviderDeleteByKey0(self.engine.0, &SPIKE_PROVIDER_GUID);
        }
    }
}

fn run_probe_wfp(cfg: &SpikeConfig) -> Result<(), String> {
    println!("\n=== WFP FWPM_CONDITION_ALE_PACKAGE_ID Dynamic Spike ===");
    println!("  target_exe = {}", cfg.target_exe);
    let (permit_sid, permit_sid_str) = derive_sid_for_pfn(&cfg.permit_pfn)?;
    let (block_sid, block_sid_str) = derive_sid_for_pfn(&cfg.block_pfn)?;
    println!("  permit_pfn = {} -> {}", cfg.permit_pfn, permit_sid_str);
    println!("  block_pfn  = {} -> {}", cfg.block_pfn, block_sid_str);

    let mut session =
        SpikeWfpSession::open_with_package_filters(&cfg.target_exe, permit_sid.0, block_sid.0)?;

    if cfg.wait_secs == 0 {
        println!("  (--wait-secs 0: filter acceptance verified; skipping net-event wait)");
        return Ok(());
    }

    session.subscribe_net_events()?;
    if session.sub1.is_none() && session.sub2.is_none() {
        return Err("both FwpmNetEventSubscribe1 and FwpmNetEventSubscribe2 failed".to_string());
    }
    println!(
        "  Observing BFE net-events for {}s (trigger target Store/backgroundTaskHost traffic now)...",
        cfg.wait_secs
    );
    let deadline = Instant::now() + Duration::from_secs(cfg.wait_secs);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(250));
    }
    session.unsubscribe_net_events();

    let captured = session
        .events
        .lock()
        .map_err(|_| "event mutex poisoned".to_string())?;
    let mut relevant = 0usize;
    println!("  Total CLASSIFY_DROP events captured: {}", captured.len());
    for ev in captured.iter() {
        let is_spike_filter = session.block_filter_ids.contains(&ev.filter_id)
            || session.permit_filter_ids.contains(&ev.filter_id);
        if is_spike_filter || ev.flag_package_id_set || ev.package_sid.is_some() {
            relevant += 1;
            println!(
                "    api={} filter_id={} spike_match={} flag_pkg={} package_sid={} dst={}:{}",
                ev.api_version,
                ev.filter_id,
                is_spike_filter,
                ev.flag_package_id_set,
                ev.package_sid.as_deref().unwrap_or("-"),
                ev.dst_ip
                    .map_or_else(|| "-".to_string(), |ip| ip.to_string()),
                ev.dst_port
            );
        }
    }
    println!("  Package/Spike-relevant drop events: {relevant}");
    Ok(())
}

fn run_curl_in_app_container(
    curl_exe: &str,
    url: &str,
    app_container_sid: PSID,
    internet_cap: &mut SID_AND_ATTRIBUTES,
) -> Result<(u32, Duration), String> {
    if url.is_empty()
        || url
            .chars()
            .any(|c| c.is_whitespace() || c.is_ascii_control() || c == '"')
    {
        return Err(format!("invalid --self-test-url `{url}`"));
    }

    let attr_list = OwnedProcThreadAttrList::new(1)?;
    let sec_caps = SECURITY_CAPABILITIES {
        AppContainerSid: app_container_sid,
        Capabilities: ptr::from_mut(internet_cap),
        CapabilityCount: 1,
        Reserved: 0,
    };

    // SAFETY: `attr_list.list` is initialized for 1 attribute and `sec_caps` stays live until `CreateProcessW`.
    unsafe {
        UpdateProcThreadAttribute(
            attr_list.list,
            0,
            usize::try_from(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES).unwrap_or(0),
            Some(ptr::from_ref(&sec_caps).cast::<c_void>()),
            std::mem::size_of::<SECURITY_CAPABILITIES>(),
            None,
            None,
        )
    }
    .map_err(|e| format!("UpdateProcThreadAttribute(SECURITY_CAPABILITIES) failed: {e}"))?;

    let si_ex = STARTUPINFOEXW {
        StartupInfo: STARTUPINFOW {
            cb: u32::try_from(std::mem::size_of::<STARTUPINFOEXW>()).unwrap_or(0),
            ..Default::default()
        },
        lpAttributeList: attr_list.list,
    };

    let app_w = encode_wide_nul(curl_exe);
    let cmd_str = format!(
        "\"{curl_exe}\" --silent --show-error --output NUL --connect-timeout 3 --max-time 4 -- {url}"
    );
    let mut cmd_w = encode_wide_nul(&cmd_str);
    let mut pi = PROCESS_INFORMATION::default();
    let flags: PROCESS_CREATION_FLAGS = EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW;

    let started = Instant::now();
    // SAFETY: `app_w`, `cmd_w`, `si_ex`, `sec_caps`, and `attr_list` remain valid across `CreateProcessW`.
    unsafe {
        CreateProcessW(
            PCWSTR(app_w.as_ptr()),
            Some(PWSTR(cmd_w.as_mut_ptr())),
            None,
            None,
            false,
            flags,
            None,
            PCWSTR::null(),
            ptr::from_ref(&si_ex.StartupInfo),
            &mut pi,
        )
    }
    .map_err(|e| format!("CreateProcessW(AppContainer curl) failed: {e}"))?;

    let proc_guard = OwnedHandle(pi.hProcess);
    let _thread_guard = OwnedHandle(pi.hThread);

    // SAFETY: waiting up to 10s for the bounded curl process to finish.
    let wait_res = unsafe { WaitForSingleObject(proc_guard.0, 10_000) };
    if wait_res != WAIT_OBJECT_0 {
        // SAFETY: `proc_guard.0` is an active child process handle; terminate on wait timeout.
        let _ = unsafe { TerminateProcess(proc_guard.0, 1) };
        return Err(format!(
            "AppContainer curl did not exit within 10s (wait={:?})",
            wait_res.0
        ));
    }
    let elapsed = started.elapsed();

    let mut exit_code: u32 = u32::MAX;
    // SAFETY: `proc_guard.0` has exited and receives its exit code.
    unsafe { GetExitCodeProcess(proc_guard.0, &mut exit_code) }
        .map_err(|e| format!("GetExitCodeProcess failed: {e}"))?;
    Ok((exit_code, elapsed))
}

fn run_self_test_wfp(cfg: &SpikeConfig) -> Result<(), String> {
    const CURL_EXE: &str = r"C:\Windows\System32\curl.exe";
    println!("\n=== FU-P4-03 Self-Test: AppContainer Isolation & Net-Event PackageSid ===");
    println!("  curl_exe = {CURL_EXE}");
    println!("  url      = {}", cfg.self_test_url);

    let cap_sid_guard = string_to_local_sid(INTERNET_CLIENT_CAPABILITY_SID)?;
    let mut internet_cap = SID_AND_ATTRIBUTES {
        Sid: PSID(cap_sid_guard.0),
        Attributes: SE_GROUP_ENABLED_U32,
    };

    let permit_profile =
        OwnedAppContainerProfile::create_fresh("LocalEDR.Spike.Permit", &[internet_cap])?;
    let block_profile =
        OwnedAppContainerProfile::create_fresh("LocalEDR.Spike.Block", &[internet_cap])?;
    println!("  Permit profile SID = {}", permit_profile.sid_str);
    println!("  Block  profile SID = {}", block_profile.sid_str);

    let mut session = SpikeWfpSession::open_with_package_filters(
        CURL_EXE,
        permit_profile.sid.0,
        block_profile.sid.0,
    )?;
    session.subscribe_net_events()?;
    if session.sub1.is_none() {
        return Err(
            "FwpmNetEventSubscribe1 failed; cannot verify v1/HEADER2 drop event and packageSid"
                .to_string(),
        );
    }

    let (permit_code, permit_elapsed) = run_curl_in_app_container(
        CURL_EXE,
        &cfg.self_test_url,
        permit_profile.sid.0,
        &mut internet_cap,
    )?;
    println!(
        "  [Test 1: Permit SID] curl exit_code={permit_code} elapsed={}ms",
        permit_elapsed.as_millis()
    );

    let (block_code, block_elapsed) = run_curl_in_app_container(
        CURL_EXE,
        &cfg.self_test_url,
        block_profile.sid.0,
        &mut internet_cap,
    )?;
    println!(
        "  [Test 2: Block  SID] curl exit_code={block_code} elapsed={}ms",
        block_elapsed.as_millis()
    );

    // Give BFE a brief window to deliver net-event callbacks before unsubscribing.
    std::thread::sleep(Duration::from_millis(1200));
    session.unsubscribe_net_events();

    let captured = session
        .events
        .lock()
        .map_err(|_| "event mutex poisoned".to_string())?;
    let mut v1_block_drops = 0usize;
    let mut v1_pkg_flag = 0usize;
    let mut v1_sid_match = 0usize;
    let mut v1_verified_events = 0usize;
    let mut v2_block_drops = 0usize;
    let mut v2_pkg_flag = 0usize;
    let mut v2_sid_match = 0usize;

    println!("  Total CLASSIFY_DROP events captured: {}", captured.len());
    for ev in captured.iter() {
        let is_block_match = session.block_filter_ids.contains(&ev.filter_id);
        let is_permit_match = session.permit_filter_ids.contains(&ev.filter_id);
        if is_block_match || is_permit_match || ev.flag_package_id_set || ev.package_sid.is_some()
        {
            println!(
                "    api={} filter_id={} block_match={} permit_match={} flag_pkg={} package_sid={} dst={}:{}",
                ev.api_version,
                ev.filter_id,
                is_block_match,
                is_permit_match,
                ev.flag_package_id_set,
                ev.package_sid.as_deref().unwrap_or("-"),
                ev.dst_ip
                    .map_or_else(|| "-".to_string(), |ip| ip.to_string()),
                ev.dst_port
            );
        }
        if is_block_match {
            let sid_matches = ev.package_sid.as_deref() == Some(block_profile.sid_str.as_str());
            if ev.api_version == "v1/HEADER2" {
                v1_block_drops += 1;
                if ev.flag_package_id_set {
                    v1_pkg_flag += 1;
                }
                if sid_matches {
                    v1_sid_match += 1;
                }
                if ev.flag_package_id_set && sid_matches {
                    v1_verified_events += 1;
                }
            } else if ev.api_version == "v2/HEADER3" {
                v2_block_drops += 1;
                if ev.flag_package_id_set {
                    v2_pkg_flag += 1;
                }
                if sid_matches {
                    v2_sid_match += 1;
                }
            }
        }
    }

    println!("\n=== Self-Test Summary ===");
    println!(
        "  Isolation: permit_exit_code={permit_code} (expect 0), block_exit_code={block_code} (expect != 0)"
    );
    println!(
        "  NetEvents v1/HEADER2: block_drops={v1_block_drops}, flag_pkg={v1_pkg_flag}, sid_match={v1_sid_match}, fully_verified={v1_verified_events}"
    );
    println!(
        "  NetEvents v2/HEADER3: block_drops={v2_block_drops}, flag_pkg={v2_pkg_flag}, sid_match={v2_sid_match}"
    );

    if permit_code != 0 || block_code == 0 {
        return Err(format!(
            "WFP package isolation assertion failed (permit_code={permit_code}, block_code={block_code})"
        ));
    }
    if v1_verified_events == 0 {
        return Err(format!(
            "missing verified v1/HEADER2 drop event matching block filter ID, FWPM_NET_EVENT_FLAG_PACKAGE_ID_SET, and block packageSid `{}`",
            block_profile.sid_str
        ));
    }
    Ok(())
}

fn main() {
    let cfg = match parse_args() {
        Ok(Some(c)) => c,
        Ok(None) => return,
        Err(err) => {
            eprintln!("Error: {err}");
            std::process::exit(2);
        }
    };

    if cfg.probe_processes {
        if let Err(err) = run_probe_processes(&cfg) {
            eprintln!("--probe-processes error: {err}");
            std::process::exit(1);
        }
    }
    if cfg.probe_wfp {
        if let Err(err) = run_probe_wfp(&cfg) {
            eprintln!("--probe-wfp error: {err}");
            std::process::exit(1);
        }
    }
    if cfg.self_test_wfp {
        if let Err(err) = run_self_test_wfp(&cfg) {
            eprintln!("--self-test-wfp error: {err}");
            std::process::exit(1);
        }
    }
}
