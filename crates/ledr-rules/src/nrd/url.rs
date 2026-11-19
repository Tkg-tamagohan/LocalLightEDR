//! HTTP/HTTPS and `file://` URL parsing and loopback host checks for NRD feeds.

use std::net::IpAddr;
use std::path::PathBuf;

/// Parsed HTTP/HTTPS URL components used by the zero-dependency WinHTTP fetcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedHttpUrl {
    pub is_https: bool,
    pub host: String,
    pub port: u16,
    pub path_and_query: String,
}

/// Parses an `http://` or `https://` URL (case-insensitive scheme, stripping `#fragment`) into
/// host, port, and path/query components.
pub fn parse_http_url(url: &str) -> Result<ParsedHttpUrl, String> {
    let trimmed = url.trim();
    let (is_https, rest_with_frag) = if trimmed
        .get(..8)
        .is_some_and(|p| p.eq_ignore_ascii_case("https://"))
    {
        (true, &trimmed[8..])
    } else if trimmed
        .get(..7)
        .is_some_and(|p| p.eq_ignore_ascii_case("http://"))
    {
        (false, &trimmed[7..])
    } else {
        return Err(format!(
            "unsupported HTTP URL scheme in `{trimmed}` (expected http:// or https://)"
        ));
    };

    let rest = rest_with_frag
        .split('#')
        .next()
        .unwrap_or(rest_with_frag);
    if rest.is_empty() || rest.bytes().any(|b| b.is_ascii_control() || b.is_ascii_whitespace()) {
        return Err(format!("invalid characters in URL `{trimmed}`"));
    }

    let (authority, path_and_query) = match rest.find(['/', '?']) {
        Some(idx) => {
            let suffix = &rest[idx..];
            let pq = if suffix.starts_with('?') {
                format!("/{suffix}")
            } else {
                suffix.to_string()
            };
            (&rest[..idx], pq)
        }
        None => (rest, "/".to_string()),
    };

    if authority.is_empty() || authority.contains('@') {
        return Err(format!("invalid or unsupported authority in URL `{trimmed}`"));
    }

    let default_port = if is_https { 443 } else { 80 };
    let (host, port) = if let Some(bracket_rest) = authority.strip_prefix('[') {
        let end = bracket_rest
            .find(']')
            .ok_or_else(|| format!("unclosed IPv6 host bracket in URL `{trimmed}`"))?;
        let host_str = &bracket_rest[..end];
        let after = &bracket_rest[end + 1..];
        let port = if after.is_empty() {
            default_port
        } else if let Some(port_str) = after.strip_prefix(':') {
            port_str
                .parse::<u16>()
                .map_err(|_| format!("invalid port `{port_str}` in URL `{trimmed}`"))?
        } else {
            return Err(format!("unexpected trailing host syntax in URL `{trimmed}`"));
        };
        (host_str.to_string(), port)
    } else if let Some((h, port_str)) = authority.rsplit_once(':') {
        let port = port_str
            .parse::<u16>()
            .map_err(|_| format!("invalid port `{port_str}` in URL `{trimmed}`"))?;
        (h.to_string(), port)
    } else {
        (authority.to_string(), default_port)
    };

    if host.is_empty() {
        return Err(format!("missing host in URL `{trimmed}`"));
    }

    Ok(ParsedHttpUrl {
        is_https,
        host,
        port,
        path_and_query,
    })
}

/// Parses a `file://` URL (case-insensitive scheme, including Windows `file:///C:/...`,
/// `file://localhost/C:/...`, and UNC `file://server/share/...`) into a local [`PathBuf`].
pub fn parse_file_url(url: &str) -> Result<PathBuf, String> {
    let trimmed = url.trim();
    if !trimmed
        .get(..7)
        .is_some_and(|p| p.eq_ignore_ascii_case("file://"))
    {
        return Err(format!("not a file:// URL: `{trimmed}`"));
    }
    let rest = &trimmed[7..];

    let decoded = percent_decode(rest)?;
    let path_str = if decoded
        .get(..10)
        .is_some_and(|p| p.eq_ignore_ascii_case("localhost/"))
    {
        normalize_windows_file_url_path(&decoded[10..])
    } else if let Some(after_slash) = decoded.strip_prefix('/') {
        normalize_windows_file_url_path(after_slash)
    } else {
        // Non-empty authority other than `localhost`: treat `C:/...` as drive path,
        // otherwise UNC `\\host\share\...`.
        let bytes = decoded.as_bytes();
        if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
            decoded.replace('/', "\\")
        } else if !decoded.is_empty() {
            format!(r"\\{}", decoded.replace('/', "\\"))
        } else {
            String::new()
        }
    };

    if path_str.is_empty() {
        return Err(format!("empty path in file:// URL `{trimmed}`"));
    }
    Ok(PathBuf::from(path_str))
}

fn normalize_windows_file_url_path(raw: &str) -> String {
    // Convert `/C:/foo/bar` or `C:/foo/bar` into `C:\foo\bar`.
    let stripped = raw.trim_start_matches('/');
    let bytes = stripped.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        stripped.replace('/', "\\")
    } else if raw.starts_with('/') {
        raw.to_string()
    } else {
        raw.replace('/', "\\")
    }
}

fn percent_decode(input: &str) -> Result<String, String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(format!("truncated percent-encoding in `{input}`"));
            }
            let hi = hex_nibble(bytes[i + 1])
                .ok_or_else(|| format!("invalid hex in percent-encoding `{input}`"))?;
            let lo = hex_nibble(bytes[i + 2])
                .ok_or_else(|| format!("invalid hex in percent-encoding `{input}`"))?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|err| format!("invalid UTF-8 in file:// URL: {err}"))
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Returns `true` when `host` is a loopback host (`localhost`, `127.0.0.0/8`, `::1`, or
/// IPv4-mapped `::ffff:127.0.0.0/104`), which is the only host class permitted over plaintext
/// `http://` for local integration testing.
pub(crate) fn is_loopback_http_host(host: &str) -> bool {
    let norm = host.trim().trim_end_matches('.');
    if norm.eq_ignore_ascii_case("localhost") {
        return true;
    }
    norm.parse::<IpAddr>()
        .is_ok_and(|ip| match crate::outbound::canonical_ip(ip) {
            IpAddr::V4(v4) => v4.is_loopback(),
            IpAddr::V6(v6) => v6.is_loopback(),
        })
}
