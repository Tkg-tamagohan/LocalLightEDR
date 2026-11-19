//! Zero-allocation UTF-16 slice and path-boundary comparison helpers (`AUTO-08`).

use crate::path_norm::starts_with_ignore_ascii_case_u16;

pub(super) const fn ascii_u16<const N: usize>(bytes: &[u8; N]) -> [u16; N] {
    let mut out = [0u16; N];
    let mut i = 0;
    while i < N {
        out[i] = bytes[i] as u16;
        i += 1;
    }
    out
}

#[inline]
const fn fold_ascii_u16(c: u16) -> u16 {
    if c >= b'A' as u16 && c <= b'Z' as u16 {
        c + 32
    } else {
        c
    }
}

#[inline]
pub(super) const fn is_sep_u16(c: u16) -> bool {
    c == b'\\' as u16 || c == b'/' as u16
}

#[inline]
pub(super) fn drives_match(expected: Option<[u16; 2]>, actual: Option<[u16; 2]>) -> bool {
    match (expected, actual) {
        (Some(a), Some(b)) => fold_ascii_u16(a[0]) == fold_ascii_u16(b[0]) && a[1] == b[1],
        (None, None) => true,
        _ => false,
    }
}

#[inline]
pub(super) fn trailing_filename_u16(path: &[u16]) -> Option<&[u16]> {
    if path.is_empty() || is_sep_u16(*path.last()?) {
        return None;
    }
    let start = path
        .iter()
        .rposition(|&c| is_sep_u16(c))
        .map_or(0, |pos| pos + 1);
    let tail = &path[start..];
    if tail.is_empty() { None } else { Some(tail) }
}

#[inline]
pub(super) fn eq_ignore_ascii_case_u16(a: &[u16], b: &[u16]) -> bool {
    a.len() == b.len() && starts_with_ignore_ascii_case_u16(a, b)
}

#[inline]
pub(super) fn starts_with_path_ignore_ascii_case_u16(haystack: &[u16], needle: &[u16]) -> bool {
    if starts_with_ignore_ascii_case_u16(haystack, needle) {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    haystack[..needle.len()]
        .iter()
        .zip(needle.iter())
        .all(|(&a, &b)| fold_ascii_u16(a) == fold_ascii_u16(b) || (is_sep_u16(a) && is_sep_u16(b)))
}

#[inline]
pub(super) fn eq_path_ignore_ascii_case_u16(a: &[u16], b: &[u16]) -> bool {
    a.len() == b.len() && starts_with_path_ignore_ascii_case_u16(a, b)
}

#[inline]
pub(super) fn ends_with_path_segment_ci_u16(haystack: &[u16], suffix: &[u16]) -> bool {
    if haystack.len() < suffix.len() {
        return false;
    }
    let offset = haystack.len() - suffix.len();
    if offset > 0 && !is_sep_u16(haystack[offset - 1]) {
        return false;
    }
    eq_path_ignore_ascii_case_u16(&haystack[offset..], suffix)
}

#[inline]
pub(super) fn find_segment_ci_u16(haystack: &[u16], needle: &[u16]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let mut idx = 0usize;
    let limit = haystack.len() - needle.len();
    while idx <= limit {
        let at_boundary = idx == 0 || is_sep_u16(haystack[idx - 1]);
        if at_boundary && starts_with_path_ignore_ascii_case_u16(&haystack[idx..], needle) {
            return Some(idx + needle.len());
        }
        // Advance directly to after the next path separator instead of scanning every code unit.
        match haystack[idx..].iter().position(|&c| is_sep_u16(c)) {
            Some(sep_rel) => idx += sep_rel + 1,
            None => break,
        }
    }
    None
}
