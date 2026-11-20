//! TDH (Trace Data Helper) ETW payload decoder and process command-line inspection helpers.

mod decode;
mod process;

pub(crate) use decode::{decode_tdh_string, inspect_raw_utf16_bytes, parse_dns_query_results};
pub(crate) use process::{filetime_100ns_to_unix_ms, filetime_to_u64, inspect_process_by_pid};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows::Win32::System::Diagnostics::Etw::{
    EVENT_HEADER_FLAG_32_BIT_HEADER, EVENT_PROPERTY_INFO, EVENT_RECORD,
    PROPERTY_DATA_DESCRIPTOR, PropertyStruct, TRACE_EVENT_INFO, TdhGetEventInformation,
    TdhGetProperty, TdhGetPropertySize,
};

#[cfg(test)]
use crate::path_norm::DosVolumeMap;

use decode::{PropMeta, decode_sid_bytes, is_ansi_in_type, read_utf16_name_if_eq};

const MAX_TEI_BYTES: u32 = 262_144;
const MAX_PROP_BYTES: u32 = 1_048_576;

/// Decodes TDH `TRACE_EVENT_INFO` metadata for an incoming ETW `EVENT_RECORD`.
///
/// Uses an inline 2 KiB stack buffer for typical manifests to avoid heap allocation
/// during hot ETW callbacks (`AUTO-08`).
pub(crate) struct TdhEventInfo<'a> {
    record: &'a EVENT_RECORD,
    stack: [u64; 256],
    stack_byte_len: usize,
    heap: Vec<u64>,
}

impl<'a> TdhEventInfo<'a> {
    #[inline]
    fn as_u64_slice(&self) -> &[u64] {
        if self.heap.is_empty() {
            &self.stack[..self.stack_byte_len.div_ceil(8).min(self.stack.len())]
        } else {
            self.heap.as_slice()
        }
    }

    #[inline]
    fn tei_bytes(&self) -> &[u8] {
        let slice = self.as_u64_slice();
        let byte_len = if self.heap.is_empty() {
            self.stack_byte_len.min(slice.len() * 8)
        } else {
            self.heap.len() * 8
        };
        // SAFETY: `slice` is a contiguous initialized `[u64]` slice and `byte_len <= slice.len() * 8`.
        unsafe { std::slice::from_raw_parts(slice.as_ptr().cast::<u8>(), byte_len) }
    }

    /// Queries TDH metadata for `record`. Returns `None` if schema decoding is unavailable.
    pub(crate) fn from_record(record: &'a EVENT_RECORD) -> Option<Self> {
        let mut stack = [0u64; 256];
        let mut buf_size: u32 = (stack.len() * 8) as u32;
        // SAFETY: `record` is valid for the callback duration and `stack` is 8-byte aligned.
        let status = unsafe {
            TdhGetEventInformation(
                record,
                None,
                Some(stack.as_mut_ptr().cast::<TRACE_EVENT_INFO>()),
                &mut buf_size,
            )
        };
        if status == 0 {
            if buf_size < std::mem::size_of::<TRACE_EVENT_INFO>() as u32
                || (buf_size as usize) > stack.len() * 8
            {
                return None;
            }
            return Some(Self {
                record,
                stack,
                stack_byte_len: buf_size as usize,
                heap: Vec::new(),
            });
        }
        if status != ERROR_INSUFFICIENT_BUFFER.0 {
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

        Some(Self {
            record,
            stack: [0u64; 256],
            stack_byte_len: 0,
            heap: buf,
        })
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

    /// Inspects raw UTF-16 code units of the first matching string property in `candidate_names`
    /// using a stack buffer so non-matching paths incur zero heap allocations (`AUTO-08`).
    pub(crate) fn inspect_first_utf16_property<F, R>(
        &self,
        candidate_names: &[&str],
        f: F,
    ) -> Option<R>
    where
        F: FnOnce(&[u16]) -> Option<R>,
    {
        for &name in candidate_names {
            if let Some(meta) = self.find_property(name) {
                return self.inspect_meta_utf16(&meta, f);
            }
        }
        None
    }

    /// Inspects two string properties (`first_name`, `second_name`, e.g., `BaseName` + `RelativeName`
    /// in `Kernel-Registry` `CreateKey`) joined by `\` in a stack UTF-16 buffer without heap
    /// allocation for paths up to 512 code units.
    pub(crate) fn inspect_joined_utf16_properties<F, R>(
        &self,
        first_name: &str,
        second_name: &str,
        f: F,
    ) -> Option<R>
    where
        F: FnOnce(&[u16]) -> Option<R>,
    {
        let mut stack = [0u16; 512];
        let mut len = 0usize;
        let mut overflow = false;

        if let Some(meta1) = self.find_property(first_name) {
            match self.read_meta_utf16_into(&meta1, &mut stack) {
                Some(Some(n1)) => len = n1,
                Some(None) => overflow = true,
                None => {}
            }
        }

        if !overflow {
            if let Some(meta2) = self.find_property(second_name) {
                let need_sep = len > 0 && stack[len - 1] != b'\\' as u16;
                let start = if need_sep {
                    if len < stack.len() {
                        stack[len] = b'\\' as u16;
                        len + 1
                    } else {
                        overflow = true;
                        len
                    }
                } else {
                    len
                };
                if !overflow {
                    match self.read_meta_utf16_into(&meta2, &mut stack[start..]) {
                        Some(Some(n2)) => {
                            if n2 == 0 && need_sep {
                                len = start - 1;
                            } else if need_sep && n2 > 0 && stack[start] == b'\\' as u16 {
                                stack.copy_within(start + 1..start + n2, start);
                                len = start + n2 - 1;
                            } else {
                                len = start + n2;
                            }
                        }
                        Some(None) => overflow = true,
                        None => {
                            if need_sep {
                                len = start - 1;
                            }
                        }
                    }
                }
            }
        }

        if !overflow {
            return if len == 0 { None } else { f(&stack[..len]) };
        }

        let part1 = self.get_string(first_name).unwrap_or_default();
        let part2 = self.get_string(second_name).unwrap_or_default();
        let joined = match (part1.is_empty(), part2.is_empty()) {
            (true, true) => return None,
            (false, true) => part1,
            (true, false) => part2,
            (false, false) => {
                if part1.ends_with('\\') || part2.starts_with('\\') {
                    format!("{part1}{part2}")
                } else {
                    format!("{part1}\\{part2}")
                }
            }
        };
        let heap: Vec<u16> = joined.encode_utf16().collect();
        f(&heap)
    }

    fn inspect_meta_utf16<F, R>(&self, meta: &PropMeta, f: F) -> Option<R>
    where
        F: FnOnce(&[u16]) -> Option<R>,
    {
        let mut stack_u16 = [0u16; 512];
        match self.read_meta_utf16_into(meta, &mut stack_u16) {
            Some(Some(len)) => f(&stack_u16[..len]),
            Some(None) => {
                let bytes = self.read_property_vec(meta)?;
                inspect_raw_utf16_bytes(&bytes, meta.in_type, f)
            }
            None => None,
        }
    }

    fn read_meta_utf16_into(&self, meta: &PropMeta, out: &mut [u16]) -> Option<Option<usize>> {
        let desc = PROPERTY_DATA_DESCRIPTOR {
            PropertyName: meta.as_ptr() as u64,
            ArrayIndex: u32::MAX,
            Reserved: 0,
        };
        let mut size: u32 = 0;
        // SAFETY: `self.record` and `desc.PropertyName` are valid NUL-terminated UTF-16 pointers.
        let status = unsafe { TdhGetPropertySize(self.record, None, &[desc], &mut size) };
        if status != 0 || size == 0 || size > MAX_PROP_BYTES {
            return None;
        }
        let size_usize = size as usize;

        if is_ansi_in_type(meta.in_type) {
            if size_usize > out.len() {
                return Some(None);
            }
            let mut ansi_buf = [0u8; 512];
            if size_usize > ansi_buf.len() {
                return Some(None);
            }
            let target = &mut ansi_buf[..size_usize];
            // SAFETY: `target` has exact `size` bytes as reported by `TdhGetPropertySize`.
            let status = unsafe { TdhGetProperty(self.record, None, &[desc], target) };
            if status != 0 {
                return None;
            }
            let mut len = 0usize;
            for &b in target.iter() {
                if b == 0 {
                    break;
                }
                if b.is_ascii() {
                    out[len] = b as u16;
                    len += 1;
                } else {
                    return Some(None);
                }
            }
            return Some(Some(len));
        }

        if size_usize > out.len() * 2 {
            return Some(None);
        }

        // SAFETY: `out` has capacity `out.len() * 2 >= size_usize` bytes and `u8` has alignment 1.
        let byte_view = unsafe {
            std::slice::from_raw_parts_mut(out.as_mut_ptr().cast::<u8>(), size_usize)
        };
        // SAFETY: `byte_view` has exact `size` bytes as reported by `TdhGetPropertySize`.
        let status = unsafe { TdhGetProperty(self.record, None, &[desc], byte_view) };
        if status != 0 {
            return None;
        }

        let unit_count = size_usize / 2;
        let len = out[..unit_count]
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(unit_count);
        Some(Some(len))
    }

    /// Reads a Windows SID (`UserSID`) property into `S-1-...` notation when present.
    pub(crate) fn get_sid_string(&self, target_name: &str) -> Option<String> {
        let meta = self.find_property(target_name)?;
        let bytes = self.read_property_vec(&meta)?;
        let is_32bit = (self.record.EventHeader.Flags as u32 & EVENT_HEADER_FLAG_32_BIT_HEADER) != 0;
        decode_sid_bytes(&bytes, meta.in_type, is_32bit)
    }

    fn find_property(&self, target_name: &str) -> Option<PropMeta> {
        let raw_bytes = self.tei_bytes();
        let u64_slice = self.as_u64_slice();
        // SAFETY: `u64_slice` is 8-byte aligned and validated to hold `TRACE_EVENT_INFO`.
        let tei = unsafe { &*(u64_slice.as_ptr().cast::<TRACE_EVENT_INFO>()) };
        let prop_count = tei.TopLevelPropertyCount as usize;
        let array_offset = std::mem::offset_of!(TRACE_EVENT_INFO, EventPropertyInfoArray);
        let needed =
            array_offset.checked_add(prop_count * std::mem::size_of::<EVENT_PROPERTY_INFO>())?;
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
            if let Some(name_buf) = read_utf16_name_if_eq(&raw_bytes[name_off..], target_name) {
                // SAFETY: `PropertyStruct` was ruled out above, so `nonStructType` is active.
                let non_struct = unsafe { prop.Anonymous1.nonStructType };
                return Some(PropMeta {
                    name_nul_u16: name_buf,
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
            PropertyName: meta.as_ptr() as u64,
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
            PropertyName: meta.as_ptr() as u64,
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

/// Inspects raw ETW string property bytes without prematurely allocating a `String` on
/// non-protected paths, returning `(CanaryCategory, normalized_target_path)` only on a match.
#[cfg(test)]
pub(crate) fn inspect_and_classify_canary_bytes(
    bytes: &[u8],
    in_type: u16,
    matcher: &crate::etw::file_canary::CanaryMatcher,
    volume_map: &DosVolumeMap,
    is_write_or_delete: bool,
) -> Option<(ledr_proto::CanaryCategory, String)> {
    inspect_raw_utf16_bytes(bytes, in_type, |u16_slice| {
        let category = matcher.classify_u16(u16_slice, volume_map, is_write_or_delete)?;
        let normalized = volume_map.normalize_u16(u16_slice);
        Some((category, normalized))
    })
}
