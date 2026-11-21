//! NRD domain normalization and feed line/byte parsing.

use std::collections::HashSet;
use std::net::IpAddr;

/// Checks exact match or multi-label parent domain suffix match using `lookup`
/// (e.g. `sub.evil-nrd.xyz` matches `evil-nrd.xyz`, while single-label TLDs like `xyz` never match).
pub(crate) fn matches_domain_or_parent<F>(domain: &str, mut lookup: F) -> bool
where
    F: FnMut(&str) -> bool,
{
    let normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }
    if lookup(&normalized) {
        return true;
    }
    let mut rest = normalized.as_str();
    while let Some((_, parent)) = rest.split_once('.') {
        if !parent.contains('.') {
            break;
        }
        if lookup(parent) {
            return true;
        }
        rest = parent;
    }
    false
}

/// Checks exact match or multi-label parent domain suffix match against `set`
/// (e.g. `sub.evil-nrd.xyz` matches `evil-nrd.xyz`, while single-label TLDs like `xyz` never match).
pub(crate) fn matches_domain_or_parent_in_set(domain: &str, set: &HashSet<String>) -> bool {
    if set.is_empty() {
        return false;
    }
    matches_domain_or_parent(domain, |candidate| set.contains(candidate))
}

/// Parses a single line from a public NRD feed (plain domain, hosts entry, or `||domain^`
/// adblock rule) into `out`, returning `true` if a valid normalized domain was written.
pub(super) fn parse_nrd_line_into(line: &str, out: &mut String) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('#')
        || trimmed.starts_with('!')
        || trimmed.starts_with(';')
    {
        return false;
    }
    let without_comment = trimmed.split('#').next().unwrap_or(trimmed).trim();
    if without_comment.is_empty() {
        return false;
    }

    let candidate = if let Some(rest) = without_comment.strip_prefix("||") {
        rest.split(['^', '/', '$', '|']).next().unwrap_or("").trim()
    } else {
        let mut tokens = without_comment.split_whitespace();
        let Some(first) = tokens.next() else {
            return false;
        };
        match tokens.next() {
            Some(second) if first.parse::<IpAddr>().is_ok() => second,
            Some(_) => return false,
            None => first,
        }
    };

    normalize_nrd_domain_into(candidate, out)
}

/// Parses a single line from a public NRD feed (plain domain, hosts entry, or `||domain^`
/// adblock rule) into a validated lowercase domain name.
pub fn parse_nrd_line(line: &str) -> Option<String> {
    let mut buf = String::new();
    parse_nrd_line_into(line, &mut buf).then_some(buf)
}

/// Validates and normalizes a domain name into `out`, returning `true` when valid.
pub(super) fn normalize_nrd_domain_into(raw: &str, out: &mut String) -> bool {
    out.clear();
    let trimmed = raw.trim().trim_end_matches('.');
    if trimmed.len() < 4 || trimmed.len() > 253 || !trimmed.contains('.') || !trimmed.is_ascii() {
        return false;
    }
    out.push_str(trimmed);
    out.make_ascii_lowercase();
    if out.parse::<IpAddr>().is_ok() {
        return false;
    }
    for label in out.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        {
            return false;
        }
    }
    true
}

/// Validates and normalizes a domain name for the NRD cache.
pub fn normalize_nrd_domain(raw: &str) -> Option<String> {
    let mut buf = String::new();
    normalize_nrd_domain_into(raw, &mut buf).then_some(buf)
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
