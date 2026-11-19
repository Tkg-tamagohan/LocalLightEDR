//! NRD domain normalization and feed line/byte parsing.

use std::collections::HashSet;
use std::net::IpAddr;

/// Checks exact match or multi-label parent domain suffix match against `set`
/// (e.g. `sub.evil-nrd.xyz` matches `evil-nrd.xyz`, while single-label TLDs like `xyz` never match).
pub(crate) fn matches_domain_or_parent_in_set(domain: &str, set: &HashSet<String>) -> bool {
    if set.is_empty() {
        return false;
    }
    let normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }
    if set.contains(&normalized) {
        return true;
    }
    let mut rest = normalized.as_str();
    while let Some((_, parent)) = rest.split_once('.') {
        if !parent.contains('.') {
            break;
        }
        if set.contains(parent) {
            return true;
        }
        rest = parent;
    }
    false
}

/// Parses a single line from a public NRD feed (plain domain, hosts entry, or `||domain^`
/// adblock rule) into a validated lowercase domain name.
pub fn parse_nrd_line(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('#')
        || trimmed.starts_with('!')
        || trimmed.starts_with(';')
    {
        return None;
    }
    let without_comment = trimmed.split('#').next().unwrap_or(trimmed).trim();
    if without_comment.is_empty() {
        return None;
    }

    let candidate = if let Some(rest) = without_comment.strip_prefix("||") {
        rest.split(['^', '/', '$', '|']).next().unwrap_or("").trim()
    } else {
        let mut tokens = without_comment.split_whitespace();
        let first = tokens.next()?;
        match tokens.next() {
            Some(second) if first.parse::<IpAddr>().is_ok() => second,
            Some(_) => return None,
            None => first,
        }
    };

    normalize_nrd_domain(candidate)
}

/// Validates and normalizes a domain name for the NRD cache.
pub fn normalize_nrd_domain(raw: &str) -> Option<String> {
    let norm = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if norm.len() < 4 || norm.len() > 253 || !norm.contains('.') {
        return None;
    }
    if norm.parse::<IpAddr>().is_ok() {
        return None;
    }
    for label in norm.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return None;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        {
            return None;
        }
    }
    Some(norm)
}

/// Parses raw NRD feed bytes into `out`, enforcing `max_entries`. Returns `(added, truncated)`.
pub fn parse_nrd_feed_bytes(
    bytes: &[u8],
    out: &mut HashSet<String>,
    max_entries: usize,
) -> (usize, bool) {
    let cap = max_entries.max(1);
    let mut added = 0usize;
    let mut truncated = false;
    let text = String::from_utf8_lossy(bytes);

    for line in text.lines() {
        let Some(domain) = parse_nrd_line(line) else {
            continue;
        };
        if out.contains(&domain) {
            continue;
        }
        if out.len() >= cap {
            truncated = true;
            break;
        }
        out.insert(domain);
        added += 1;
    }

    (added, truncated)
}
