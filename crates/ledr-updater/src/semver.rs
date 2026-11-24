//! Strict SemVer 2.0.0 parsing and pre-release comparison (standard library only).

use std::cmp::Ordering;

use crate::{SemVer, UpdaterError};

/// Parses a strict `MAJOR.MINOR.PATCH[-PRERELEASE]` string.
///
/// Rejects leading `v`/`V`, whitespace, `+build` metadata, leading zeros on numeric
/// components, empty pre-release (`1.0.0-`), and invalid identifier characters.
pub(crate) fn parse(input: &str) -> Result<SemVer, UpdaterError> {
    if input.is_empty()
        || input.starts_with('v')
        || input.starts_with('V')
        || input.bytes().any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        || input.contains('+')
    {
        return Err(UpdaterError::InvalidSemVer(input.to_string()));
    }

    let (core, pre_release) = match input.split_once('-') {
        Some((core_part, pre_part)) => {
            validate_prerelease(pre_part, input)?;
            (core_part, Some(pre_part.to_string()))
        }
        None => (input, None),
    };

    let mut parts = core.split('.');
    let major_str = parts
        .next()
        .ok_or_else(|| UpdaterError::InvalidSemVer(input.to_string()))?;
    let minor_str = parts
        .next()
        .ok_or_else(|| UpdaterError::InvalidSemVer(input.to_string()))?;
    let patch_str = parts
        .next()
        .ok_or_else(|| UpdaterError::InvalidSemVer(input.to_string()))?;
    if parts.next().is_some() {
        return Err(UpdaterError::InvalidSemVer(input.to_string()));
    }

    let major = parse_numeric_component(major_str, input)?;
    let minor = parse_numeric_component(minor_str, input)?;
    let patch = parse_numeric_component(patch_str, input)?;

    Ok(SemVer {
        major,
        minor,
        patch,
        pre_release,
    })
}

fn parse_numeric_component(part: &str, full_input: &str) -> Result<u64, UpdaterError> {
    if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
        return Err(UpdaterError::InvalidSemVer(full_input.to_string()));
    }
    if part.len() > 1 && part.starts_with('0') {
        return Err(UpdaterError::InvalidSemVer(full_input.to_string()));
    }
    part.parse::<u64>()
        .map_err(|_| UpdaterError::InvalidSemVer(full_input.to_string()))
}

fn validate_prerelease(pre: &str, full_input: &str) -> Result<(), UpdaterError> {
    if pre.is_empty() {
        return Err(UpdaterError::InvalidSemVer(full_input.to_string()));
    }
    for seg in pre.split('.') {
        if seg.is_empty()
            || !seg
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'-'))
        {
            return Err(UpdaterError::InvalidSemVer(full_input.to_string()));
        }
        if seg.bytes().all(|b| b.is_ascii_digit()) && seg.len() > 1 && seg.starts_with('0') {
            return Err(UpdaterError::InvalidSemVer(full_input.to_string()));
        }
    }
    Ok(())
}

/// Compares two SemVer 2.0.0 pre-release strings (`SemVer 2.0.0 §11.4`).
pub(crate) fn compare_prerelease(a: &str, b: &str) -> Ordering {
    let mut a_iter = a.split('.');
    let mut b_iter = b.split('.');

    loop {
        match (a_iter.next(), b_iter.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(pa), Some(pb)) => {
                let a_is_num = !pa.is_empty() && pa.bytes().all(|c| c.is_ascii_digit());
                let b_is_num = !pb.is_empty() && pb.bytes().all(|c| c.is_ascii_digit());
                let ord = match (a_is_num, b_is_num) {
                    (true, true) => {
                        let ta = pa.trim_start_matches('0');
                        let tb = pb.trim_start_matches('0');
                        ta.len().cmp(&tb.len()).then_with(|| ta.cmp(tb))
                    }
                    (true, false) => Ordering::Less,
                    (false, true) => Ordering::Greater,
                    (false, false) => pa.cmp(pb),
                };
                if ord != Ordering::Equal {
                    return ord;
                }
            }
        }
    }
}
