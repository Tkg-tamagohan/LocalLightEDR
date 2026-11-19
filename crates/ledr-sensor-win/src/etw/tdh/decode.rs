//! TDH UTF-16/ANSI property string, SID, and DNS QueryResults decoders.

use std::net::IpAddr;

use windows::Win32::System::Diagnostics::Etw::{
    TDH_INTYPE_ANSISTRING, TDH_INTYPE_BINARY, TDH_INTYPE_COUNTEDANSISTRING,
    TDH_INTYPE_MANIFEST_COUNTEDANSISTRING, TDH_INTYPE_WBEMSID,
};

pub(super) enum PropNameBuf {
    Stack([u16; 64]),
    Heap(Vec<u16>),
}

pub(super) struct PropMeta {
    pub(super) name_nul_u16: PropNameBuf,
    pub(super) in_type: u16,
}

impl PropMeta {
    #[inline]
    pub(super) fn as_ptr(&self) -> *const u16 {
        match &self.name_nul_u16 {
            PropNameBuf::Stack(buf) => buf.as_ptr(),
            PropNameBuf::Heap(vec) => vec.as_ptr(),
        }
    }
}

pub(super) fn read_utf16_name_if_eq(bytes: &[u8], expected_ascii: &str) -> Option<PropNameBuf> {
    if expected_ascii.len() >= 64 {
        let (matched, vec) = read_utf16_name_and_eq_heap(bytes, expected_ascii);
        return if matched {
            Some(PropNameBuf::Heap(vec))
        } else {
            None
        };
    }

    let mut stack = [0u16; 64];
    let mut expected_iter = expected_ascii.bytes();

    for (len, &chunk) in bytes.as_chunks::<2>().0.iter().enumerate() {
        let ch = u16::from_le_bytes(chunk);
        if ch == 0 {
            if expected_iter.next().is_some() {
                return None;
            }
            if len >= stack.len() {
                return None;
            }
            stack[len] = 0;
            return Some(PropNameBuf::Stack(stack));
        }
        match expected_iter.next() {
            Some(exp) if ch <= 0x7F && (ch as u8).eq_ignore_ascii_case(&exp) => {}
            _ => return None,
        }
        if len + 1 >= stack.len() {
            return None;
        }
        stack[len] = ch;
    }

    None
}

fn read_utf16_name_and_eq_heap(bytes: &[u8], expected_ascii: &str) -> (bool, Vec<u16>) {
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

#[inline]
pub(super) const fn is_ansi_in_type(in_type: u16) -> bool {
    in_type == TDH_INTYPE_ANSISTRING.0 as u16
        || in_type == TDH_INTYPE_COUNTEDANSISTRING.0 as u16
        || in_type == TDH_INTYPE_MANIFEST_COUNTEDANSISTRING.0 as u16
}

/// Inspects raw string property bytes (`UnicodeString` UTF-16LE or `AnsiString`) via a stack
/// UTF-16 buffer for paths up to 512 code units, avoiding heap allocation on non-matching I/O.
pub(crate) fn inspect_raw_utf16_bytes<F, R>(bytes: &[u8], in_type: u16, f: F) -> Option<R>
where
    F: FnOnce(&[u16]) -> Option<R>,
{
    if is_ansi_in_type(in_type) {
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        let trimmed = &bytes[..end];
        if trimmed.len() <= 512 && trimmed.iter().all(|b| b.is_ascii()) {
            let mut stack = [0u16; 512];
            for (dst, &src) in stack.iter_mut().zip(trimmed.iter()) {
                *dst = src as u16;
            }
            return f(&stack[..trimmed.len()]);
        }
        let text = String::from_utf8_lossy(trimmed);
        let heap: Vec<u16> = text.encode_utf16().collect();
        return f(&heap);
    }

    if bytes.len() < 2 {
        return None;
    }

    if bytes.len() <= 1024 {
        let mut stack = [0u16; 512];
        let mut len = 0usize;
        for &chunk in bytes.as_chunks::<2>().0.iter() {
            let ch = u16::from_le_bytes(chunk);
            if ch == 0 {
                break;
            }
            stack[len] = ch;
            len += 1;
        }
        return f(&stack[..len]);
    }

    let mut heap = Vec::with_capacity(bytes.len() / 2);
    for &chunk in bytes.as_chunks::<2>().0.iter() {
        let ch = u16::from_le_bytes(chunk);
        if ch == 0 {
            break;
        }
        heap.push(ch);
    }
    f(&heap)
}

pub(crate) fn decode_tdh_string(bytes: &[u8], in_type: u16) -> String {
    if is_ansi_in_type(in_type) {
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

pub(super) fn decode_sid_bytes(bytes: &[u8], in_type: u16, is_32bit: bool) -> Option<String> {
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
