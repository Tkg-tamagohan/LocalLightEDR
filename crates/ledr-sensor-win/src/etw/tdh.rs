//! TDH (Trace Data Helper) ETW payload decoder and process command-line inspection helpers.

use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

use windows::core::PWSTR;
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, FILETIME};
use windows::Win32::System::Diagnostics::Etw::{
    EVENT_HEADER_FLAG_32_BIT_HEADER, EVENT_PROPERTY_INFO, EVENT_RECORD,
    PROPERTY_DATA_DESCRIPTOR, PropertyStruct, TDH_INTYPE_ANSISTRING, TDH_INTYPE_BINARY,
    TDH_INTYPE_COUNTEDANSISTRING, TDH_INTYPE_MANIFEST_COUNTEDANSISTRING, TDH_INTYPE_WBEMSID,
    TRACE_EVENT_INFO, TdhGetEventInformation, TdhGetProperty, TdhGetPropertySize,
};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW,
};

use crate::OwnedHandle;
use crate::path_norm::DosVolumeMap;

const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
const PROCESS_COMMAND_LINE_INFORMATION: u32 = 60;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;
const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023_u32 as i32;
const MAX_TEI_BYTES: u32 = 262_144;
const MAX_PROP_BYTES: u32 = 1_048_576;

#[link(name = "ntdll.dll", kind = "raw-dylib", modifiers = "+verbatim")]
extern "system" {
    fn NtQueryInformationProcess(
        process_handle: windows::Win32::Foundation::HANDLE,
        process_information_class: u32,
        process_information: *mut c_void,
        process_information_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

#[repr(C)]
struct NtUnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

/// Process attributes inspected via Win32 / `ntdll` process handle queries.
pub(crate) struct ProcessInspectInfo {
    pub(crate) create_time_100ns: u64,
    pub(crate) exe_path: Option<String>,
    pub(crate) command_line: Option<String>,
}

/// Returns current Unix epoch time in milliseconds.
pub(crate) fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Converts a Windows 100ns `FILETIME` value to Unix epoch milliseconds.
pub(crate) fn filetime_100ns_to_unix_ms(ft_100ns: u64) -> i64 {
    if ft_100ns >= WINDOWS_TO_UNIX_EPOCH_100NS {
        ((ft_100ns - WINDOWS_TO_UNIX_EPOCH_100NS) / 10_000) as i64
    } else {
        now_unix_ms()
    }
}

/// Combines `FILETIME` low/high parts into a `u64` 100ns timestamp.
#[inline]
pub(crate) fn filetime_to_u64(ft: FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64)
}

/// Inspects creation time, full Win32 image path, and command line for `pid` when accessible.
pub(crate) fn inspect_process_by_pid(
    pid: u32,
    volume_map: Option<&DosVolumeMap>,
) -> Option<ProcessInspectInfo> {
    if pid == 0 {
        return None;
    }

    // SAFETY: `OpenProcess` with `PROCESS_QUERY_LIMITED_INFORMATION` is read-only metadata access.
    let raw_handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let handle = OwnedHandle::new(raw_handle)?;

    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: `handle` is an open process handle and all four `FILETIME` pointers are stack-allocated.
    let create_time_100ns = if unsafe {
        GetProcessTimes(
            handle.as_raw(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    }
    .is_ok()
    {
        filetime_to_u64(creation)
    } else {
        0
    };

    let mut path_buf = vec![0u16; 1024];
    let mut path_len = path_buf.len() as u32;
    // SAFETY: `handle` is valid and `path_buf` has `path_len` `u16` elements.
    let exe_path = if unsafe {
        QueryFullProcessImageNameW(
            handle.as_raw(),
            PROCESS_NAME_WIN32,
            PWSTR(path_buf.as_mut_ptr()),
            &mut path_len,
        )
    }
    .is_ok()
        && path_len > 0
    {
        let raw_slice = &path_buf[..(path_len as usize).min(path_buf.len())];
        Some(match volume_map {
            Some(map) => map.normalize_u16(raw_slice),
            None => String::from_utf16_lossy(raw_slice),
        })
    } else {
        None
    };

    let command_line = query_handle_command_line(handle.as_raw());

    Some(ProcessInspectInfo {
        create_time_100ns,
        exe_path,
        command_line,
    })
}

fn query_handle_command_line(handle: windows::Win32::Foundation::HANDLE) -> Option<String> {
    let mut buf = vec![0u64; 512]; // 4 KiB, 8-byte aligned
    let mut ret_len: u32 = 0;

    // SAFETY: `handle` is an open process handle; `buf` is 8-byte aligned writable storage.
    let mut status = unsafe {
        NtQueryInformationProcess(
            handle,
            PROCESS_COMMAND_LINE_INFORMATION,
            buf.as_mut_ptr().cast::<c_void>(),
            (buf.len() * 8) as u32,
            &mut ret_len,
        )
    };

    if (status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL)
        && ret_len > (buf.len() * 8) as u32
        && ret_len <= 65_536
    {
        buf.resize((ret_len as usize).div_ceil(8), 0);
        // SAFETY: same preconditions as above with resized buffer.
        status = unsafe {
            NtQueryInformationProcess(
                handle,
                PROCESS_COMMAND_LINE_INFORMATION,
                buf.as_mut_ptr().cast::<c_void>(),
                (buf.len() * 8) as u32,
                &mut ret_len,
            )
        };
    }

    if status != 0 {
        return None;
    }

    let total_bytes = buf.len() * 8;
    if total_bytes < std::mem::size_of::<NtUnicodeString>() {
        return None;
    }

    // SAFETY: `buf` is 8-byte aligned and at least `size_of::<NtUnicodeString>()` bytes.
    let us = unsafe { &*(buf.as_ptr().cast::<NtUnicodeString>()) };
    if us.length == 0 || us.buffer.is_null() || (us.length & 1) != 0 {
        return Some(String::new());
    }

    let buf_start = buf.as_ptr() as usize;
    let buf_end = buf_start + total_bytes;
    let str_start = us.buffer as usize;
    let str_len_bytes = us.length as usize;
    if str_start < buf_start || str_start.saturating_add(str_len_bytes) > buf_end {
        return None;
    }

    // SAFETY: verified `str_start..str_start + str_len_bytes` lies completely inside `buf`.
    let slice = unsafe { std::slice::from_raw_parts(us.buffer, str_len_bytes / 2) };
    Some(String::from_utf16_lossy(slice))
}

/// Decodes TDH `TRACE_EVENT_INFO` metadata for an incoming ETW `EVENT_RECORD`.
pub(crate) struct TdhEventInfo<'a> {
    record: &'a EVENT_RECORD,
    buf: Vec<u64>,
}

impl<'a> TdhEventInfo<'a> {
    /// Queries TDH metadata for `record`. Returns `None` if schema decoding is unavailable.
    pub(crate) fn from_record(record: &'a EVENT_RECORD) -> Option<Self> {
        let mut buf_size: u32 = 0;
        // SAFETY: `record` is a valid ETW `EVENT_RECORD` reference for the callback duration.
        let status = unsafe { TdhGetEventInformation(record, None, None, &mut buf_size) };
        if status != ERROR_INSUFFICIENT_BUFFER.0 && status != 0 {
            return None;
        }
        if buf_size < std::mem::size_of::<TRACE_EVENT_INFO>() as u32 || buf_size > MAX_TEI_BYTES {
            return None;
        }

        let mut buf = vec![0u64; (buf_size as usize).div_ceil(8)];
        // SAFETY: `buf` is 8-byte aligned and sized to `buf_size` bytes.
        let status = unsafe {
            TdhGetEventInformation(
                record,
                None,
                Some(buf.as_mut_ptr().cast::<TRACE_EVENT_INFO>()),
                &mut buf_size,
            )
        };
        if status != 0 {
            return None;
        }

        Some(Self { record, buf })
    }

    /// Reads an unsigned 32-bit property matching `target_name` (case-insensitive).
    pub(crate) fn get_u32(&self, target_name: &str) -> Option<u32> {
        let meta = self.find_property(target_name)?;
        let mut stack = [0u8; 32];
        let bytes = self.read_property_small(&meta, &mut stack)?;
        if bytes.len() == 4 {
            Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        } else if bytes.len() == 8 {
            Some(u64::from_le_bytes(bytes[..8].try_into().ok()?) as u32)
        } else if bytes.len() == 2 {
            Some(u16::from_le_bytes([bytes[0], bytes[1]]) as u32)
        } else {
            None
        }
    }

    /// Reads an unsigned 16-bit property matching `target_name` (case-insensitive).
    pub(crate) fn get_u16(&self, target_name: &str) -> Option<u16> {
        let meta = self.find_property(target_name)?;
        let mut stack = [0u8; 32];
        let bytes = self.read_property_small(&meta, &mut stack)?;
        if bytes.len() >= 2 {
            Some(u16::from_le_bytes([bytes[0], bytes[1]]))
        } else {
            None
        }
    }

    /// Reads a big-endian network port property (`TDH_OUTTYPE_PORT`) as host `u16`.
    pub(crate) fn get_port_be(&self, target_name: &str) -> Option<u16> {
        let meta = self.find_property(target_name)?;
        let mut stack = [0u8; 32];
        let bytes = self.read_property_small(&meta, &mut stack)?;
        if bytes.len() >= 2 {
            Some(u16::from_be_bytes([bytes[0], bytes[1]]))
        } else {
            None
        }
    }

    /// Reads an unsigned 64-bit / `FILETIME` property matching `target_name`.
    pub(crate) fn get_u64(&self, target_name: &str) -> Option<u64> {
        let meta = self.find_property(target_name)?;
        let mut stack = [0u8; 32];
        let bytes = self.read_property_small(&meta, &mut stack)?;
        if bytes.len() >= 8 {
            Some(u64::from_le_bytes(bytes[..8].try_into().ok()?))
        } else if bytes.len() == 4 {
            Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64)
        } else {
            None
        }
    }

    /// Reads an IPv4 or IPv6 address property (`daddr`).
    pub(crate) fn get_ip_addr(&self, target_name: &str) -> Option<IpAddr> {
        let meta = self.find_property(target_name)?;
        let mut stack = [0u8; 32];
        let bytes = self.read_property_small(&meta, &mut stack)?;
        if bytes.len() == 4 {
            Some(IpAddr::V4(Ipv4Addr::new(
                bytes[0], bytes[1], bytes[2], bytes[3],
            )))
        } else if bytes.len() >= 16 {
            let octets: [u8; 16] = bytes[..16].try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        } else {
            None
        }
    }

    /// Reads a string (Unicode, ANSI, or UTF-16LE/UTF-8 binary script) property.
    pub(crate) fn get_string(&self, target_name: &str) -> Option<String> {
        let meta = self.find_property(target_name)?;
        let bytes = self.read_property_vec(&meta)?;
        Some(decode_tdh_string(&bytes, meta.in_type))
    }

    /// Reads a Windows SID (`UserSID`) property into `S-1-...` notation when present.
    pub(crate) fn get_sid_string(&self, target_name: &str) -> Option<String> {
        let meta = self.find_property(target_name)?;
        let bytes = self.read_property_vec(&meta)?;
        let is_32bit = (self.record.EventHeader.Flags as u32 & EVENT_HEADER_FLAG_32_BIT_HEADER) != 0;
        decode_sid_bytes(&bytes, meta.in_type, is_32bit)
    }

    fn tei_bytes(&self) -> &[u8] {
        // SAFETY: `self.buf` is a contiguous initialized `Vec<u64>`.
        unsafe { std::slice::from_raw_parts(self.buf.as_ptr().cast::<u8>(), self.buf.len() * 8) }
    }

    fn find_property(&self, target_name: &str) -> Option<PropMeta> {
        let raw_bytes = self.tei_bytes();
        // SAFETY: `self.buf` is 8-byte aligned and validated to hold `TRACE_EVENT_INFO`.
        let tei = unsafe { &*(self.buf.as_ptr().cast::<TRACE_EVENT_INFO>()) };
        let prop_count = tei.TopLevelPropertyCount as usize;
        let array_offset = std::mem::offset_of!(TRACE_EVENT_INFO, EventPropertyInfoArray);
        let needed = array_offset.checked_add(prop_count * std::mem::size_of::<EVENT_PROPERTY_INFO>())?;
        if needed > raw_bytes.len() {
            return None;
        }

        // SAFETY: bounds checked above against `raw_bytes.len()`.
        let props = unsafe {
            std::slice::from_raw_parts(tei.EventPropertyInfoArray.as_ptr(), prop_count)
        };

        for prop in props {
            if (prop.Flags.0 & PropertyStruct.0) != 0 {
                continue;
            }
            let name_off = prop.NameOffset as usize;
            if name_off >= raw_bytes.len() {
                continue;
            }
            let (matched, name_nul_u16) = read_utf16_name_and_eq(&raw_bytes[name_off..], target_name);
            if matched {
                // SAFETY: `PropertyStruct` was ruled out above, so `nonStructType` is active.
                let non_struct = unsafe { prop.Anonymous1.nonStructType };
                return Some(PropMeta {
                    name_nul_u16,
                    in_type: non_struct.InType,
                });
            }
        }
        None
    }

    fn read_property_small<'b>(
        &self,
        meta: &PropMeta,
        stack: &'b mut [u8; 32],
    ) -> Option<&'b [u8]> {
        let desc = PROPERTY_DATA_DESCRIPTOR {
            PropertyName: meta.name_nul_u16.as_ptr() as u64,
            ArrayIndex: u32::MAX,
            Reserved: 0,
        };
        let mut size: u32 = 0;
        // SAFETY: `self.record` and `desc.PropertyName` are valid NUL-terminated UTF-16 pointers.
        let status = unsafe { TdhGetPropertySize(self.record, None, &[desc], &mut size) };
        if status != 0 || size == 0 || (size as usize) > stack.len() {
            return None;
        }
        let target = &mut stack[..size as usize];
        // SAFETY: `target` has exact `size` bytes as reported by `TdhGetPropertySize`.
        let status = unsafe { TdhGetProperty(self.record, None, &[desc], target) };
        if status != 0 {
            return None;
        }
        Some(target)
    }

    fn read_property_vec(&self, meta: &PropMeta) -> Option<Vec<u8>> {
        let desc = PROPERTY_DATA_DESCRIPTOR {
            PropertyName: meta.name_nul_u16.as_ptr() as u64,
            ArrayIndex: u32::MAX,
            Reserved: 0,
        };
        let mut size: u32 = 0;
        // SAFETY: `self.record` and `desc.PropertyName` are valid NUL-terminated UTF-16 pointers.
        let status = unsafe { TdhGetPropertySize(self.record, None, &[desc], &mut size) };
        if status != 0 || size == 0 || size > MAX_PROP_BYTES {
            return None;
        }
        let mut out = vec![0u8; size as usize];
        // SAFETY: `out` has exact `size` bytes as reported by `TdhGetPropertySize`.
        let status = unsafe { TdhGetProperty(self.record, None, &[desc], &mut out) };
        if status != 0 {
            return None;
        }
        Some(out)
    }
}

struct PropMeta {
    name_nul_u16: Vec<u16>,
    in_type: u16,
}

fn read_utf16_name_and_eq(bytes: &[u8], expected_ascii: &str) -> (bool, Vec<u16>) {
    let mut name_u16 = Vec::new();
    let mut expected_iter = expected_ascii.bytes();
    let mut matches = true;

    for &chunk in bytes.as_chunks::<2>().0.iter() {
        let ch = u16::from_le_bytes(chunk);
        if ch == 0 {
            if expected_iter.next().is_some() {
                matches = false;
            }
            name_u16.push(0);
            return (matches, name_u16);
        }
        if matches {
            match expected_iter.next() {
                Some(exp) if ch <= 0x7F && (ch as u8).eq_ignore_ascii_case(&exp) => {}
                _ => matches = false,
            }
        }
        name_u16.push(ch);
        if name_u16.len() > 256 {
            return (false, Vec::new());
        }
    }

    (false, Vec::new())
}

pub(crate) fn decode_tdh_string(bytes: &[u8], in_type: u16) -> String {
    if in_type == TDH_INTYPE_ANSISTRING.0 as u16
        || in_type == TDH_INTYPE_COUNTEDANSISTRING.0 as u16
        || in_type == TDH_INTYPE_MANIFEST_COUNTEDANSISTRING.0 as u16
    {
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        return String::from_utf8_lossy(&bytes[..end]).into_owned();
    }

    if in_type == TDH_INTYPE_BINARY.0 as u16 {
        if bytes.len() >= 2 && (bytes.len() & 1) == 0 {
            let zero_hi_count = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .filter(|c| c[1] == 0)
                .count();
            if zero_hi_count * 2 >= bytes.len() / 2 {
                return decode_utf16_le(bytes);
            }
        }
        let trimmed = trim_trailing_zero_bytes(bytes);
        return String::from_utf8_lossy(trimmed).into_owned();
    }

    decode_utf16_le(bytes)
}

fn decode_utf16_le(bytes: &[u8]) -> String {
    let mut u16s = Vec::with_capacity(bytes.len() / 2);
    for &chunk in bytes.as_chunks::<2>().0.iter() {
        let ch = u16::from_le_bytes(chunk);
        if ch == 0 {
            break;
        }
        u16s.push(ch);
    }
    String::from_utf16_lossy(&u16s)
}

fn trim_trailing_zero_bytes(mut bytes: &[u8]) -> &[u8] {
    while let Some(&0) = bytes.last() {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn decode_sid_bytes(bytes: &[u8], in_type: u16, is_32bit: bool) -> Option<String> {
    let sid_slice = if in_type == TDH_INTYPE_WBEMSID.0 as u16 {
        let ptr_size = if is_32bit { 4 } else { 8 };
        let header = ptr_size * 2;
        if bytes.len() <= header {
            return None;
        }
        &bytes[header..]
    } else {
        bytes
    };

    if sid_slice.len() < 8 {
        return None;
    }
    let revision = sid_slice[0];
    let sub_count = sid_slice[1] as usize;
    if revision != 1 || sid_slice.len() < 8 + sub_count * 4 {
        return None;
    }

    let authority = u64::from_be_bytes([
        0,
        0,
        sid_slice[2],
        sid_slice[3],
        sid_slice[4],
        sid_slice[5],
        sid_slice[6],
        sid_slice[7],
    ]);

    let mut out = format!("S-{revision}-{authority}");
    for i in 0..sub_count {
        let off = 8 + i * 4;
        let sub = u32::from_le_bytes([
            sid_slice[off],
            sid_slice[off + 1],
            sid_slice[off + 2],
            sid_slice[off + 3],
        ]);
        out.push('-');
        out.push_str(&sub.to_string());
    }
    Some(out)
}

/// Extracts IPv4 and IPv6 addresses from `Microsoft-Windows-DNS-Client` `QueryResults` strings
/// (e.g. `"type:  1 93.184.216.34;type: 28 2606:2800:220:1::1;"`).
pub(crate) fn parse_dns_query_results(raw: &str) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    for token in raw.split([';', ' ', ',', '\t', '\r', '\n']) {
        let trimmed = token.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(ip) = trimmed.parse::<IpAddr>() else {
            continue;
        };
        if !ips.contains(&ip) {
            ips.push(ip);
        }
    }
    ips
}
