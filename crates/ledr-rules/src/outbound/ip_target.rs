//! Network destination canonicalization, CIDR parsing, and target matching.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Canonicalizes an [`IpAddr`] by unwrapping IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`)
/// into their underlying [`IpAddr::V4`].
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
    }
}

/// Returns `true` when `ip` is a publicly routable / external destination (excluding loopback,
/// RFC1918 private LAN, link-local, multicast, broadcast, unspecified, IPv6 ULA, and IPv4-mapped
/// local IPv6 addresses).
pub fn is_external_ip(ip: IpAddr) -> bool {
    match canonical_ip(ip) {
        IpAddr::V4(v4) => is_external_ipv4(v4),
        IpAddr::V6(v6) => is_external_ipv6(v6),
    }
}

fn is_external_ipv4(v4: Ipv4Addr) -> bool {
    !v4.is_loopback()
        && !v4.is_private()
        && !v4.is_link_local()
        && !v4.is_broadcast()
        && !v4.is_multicast()
        && !v4.is_unspecified()
}

fn is_external_ipv6(v6: Ipv6Addr) -> bool {
    let seg0 = v6.segments()[0];
    let is_ula = (seg0 & 0xfe00) == 0xfc00; // fc00::/7
    let is_unicast_link_local = (seg0 & 0xffc0) == 0xfe80; // fe80::/10
    !v6.is_loopback()
        && !v6.is_unspecified()
        && !v6.is_multicast()
        && !is_ula
        && !is_unicast_link_local
}

/// Parses an IPv4 or IPv6 CIDR target (`a.b.c.d/prefix` or `addr/prefix`), normalizing the
/// network address by zeroing host bits and canonicalizing IPv4-mapped IPv6 prefixes (`>= 96`).
pub fn parse_cidr_target(pattern: &str) -> Result<(IpAddr, u8), String> {
    let trimmed = pattern.trim();
    let Some((addr_part, prefix_part)) = trimmed.split_once('/') else {
        return Err(format!("invalid CIDR `{trimmed}`: missing `/prefix`"));
    };
    if prefix_part.contains('/') {
        return Err(format!("invalid CIDR `{trimmed}`: multiple `/` separators"));
    }
    let addr_str = addr_part.trim();
    let prefix_str = prefix_part.trim();
    if prefix_str.is_empty() || !prefix_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!(
            "invalid CIDR prefix length in `{trimmed}`: expected unsigned integer"
        ));
    }
    let prefix_len: u8 = prefix_str
        .parse::<u8>()
        .map_err(|_| format!("invalid CIDR prefix length in `{trimmed}`"))?;
    let addr: IpAddr = addr_str
        .parse()
        .map_err(|_| format!("invalid CIDR base IP `{addr_str}` in `{trimmed}`"))?;

    match addr {
        IpAddr::V4(v4) => {
            if prefix_len > 32 {
                return Err(format!(
                    "IPv4 CIDR prefix length {prefix_len} out of range 0..=32 in `{trimmed}`"
                ));
            }
            let mask: u32 = if prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - prefix_len)
            };
            Ok((IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask)), prefix_len))
        }
        IpAddr::V6(v6) => {
            if prefix_len > 128 {
                return Err(format!(
                    "IPv6 CIDR prefix length {prefix_len} out of range 0..=128 in `{trimmed}`"
                ));
            }
            if let Some(mapped_v4) = v6.to_ipv4_mapped() {
                if prefix_len >= 96 {
                    let v4_prefix = prefix_len - 96;
                    let mask: u32 = if v4_prefix == 0 {
                        0
                    } else {
                        u32::MAX << (32 - v4_prefix)
                    };
                    return Ok((
                        IpAddr::V4(Ipv4Addr::from(u32::from(mapped_v4) & mask)),
                        v4_prefix,
                    ));
                }
            }
            let mask: u128 = if prefix_len == 0 {
                0
            } else {
                u128::MAX << (128 - prefix_len)
            };
            Ok((
                IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask)),
                prefix_len,
            ))
        }
    }
}

fn matches_cidr(network: IpAddr, prefix_len: u8, canon_dst: IpAddr) -> bool {
    match (network, canon_dst) {
        (IpAddr::V4(net), IpAddr::V4(dst)) => {
            if prefix_len > 32 {
                return false;
            }
            let mask: u32 = if prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - prefix_len)
            };
            (u32::from(dst) & mask) == u32::from(net)
        }
        (IpAddr::V6(net), IpAddr::V6(dst)) => {
            if prefix_len > 128 {
                return false;
            }
            let mask: u128 = if prefix_len == 0 {
                0
            } else {
                u128::MAX << (128 - prefix_len)
            };
            (u128::from(dst) & mask) == u128::from(net)
        }
        _ => false,
    }
}

/// Matches a network rule target pattern (`allowed_target`) against `dst_ip` and optional
/// `domain_hint` (canonical IP comparison supporting IPv4-mapped IPv6 and uncompressed IPv6,
/// IPv4/IPv6 CIDR matching, plus ASCII case-insensitive wildcard `*` matching normalizing trailing
/// DNS dots).
pub fn matches_network_target(
    pattern: &str,
    dst_ip: IpAddr,
    domain_hint: Option<&str>,
) -> bool {
    let pat = pattern.trim().trim_end_matches('.');
    if pat.is_empty() {
        return true;
    }
    let canon_dst = canonical_ip(dst_ip);
    if pat.contains('/') {
        return parse_cidr_target(pat)
            .is_ok_and(|(net, prefix_len)| matches_cidr(net, prefix_len, canon_dst));
    }
    if !pat.contains('*') {
        if let Ok(pat_ip) = pat.parse::<IpAddr>() {
            if canonical_ip(pat_ip) == canon_dst {
                return true;
            }
        }
    }
    let ip_str = canon_dst.to_string();
    if matches_wildcard_ascii_ci(&ip_str, pat) {
        return true;
    }
    if let Some(domain) = domain_hint {
        let norm_domain = domain.trim().trim_end_matches('.');
        if !norm_domain.is_empty() && matches_wildcard_ascii_ci(norm_domain, pat) {
            return true;
        }
    }
    false
}

fn matches_wildcard_ascii_ci(haystack: &str, pattern: &str) -> bool {
    let s: Vec<u8> = haystack
        .bytes()
        .map(|b| b.to_ascii_lowercase())
        .collect();
    let p: Vec<u8> = pattern
        .bytes()
        .map(|b| b.to_ascii_lowercase())
        .collect();

    let (mut si, mut pi) = (0usize, 0usize);
    let (mut star_pi, mut match_si) = (None, 0usize);

    while si < s.len() {
        if pi < p.len() && p[pi] == s[si] {
            si += 1;
            pi += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star_pi = Some(pi);
            match_si = si;
            pi += 1;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            match_si += 1;
            si = match_si;
        } else {
            return false;
        }
    }

    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}
