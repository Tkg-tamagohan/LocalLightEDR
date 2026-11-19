//! Daily Newly Registered Domain (NRD) feed fetcher and bounded local cache (`決定記録 L-14`).
//!
//! Fetches public 14-day NRD feeds (`hagezi/nrd` `nrd7.txt` + `nrd14-8.txt` by default) via
//! Windows built-in `winhttp.dll` (`raw-dylib`, zero external HTTP crate dependencies) or local
//! `file://` URLs for deterministic offline tests. Enforces strict entry (`50,000`) and response
//! byte (`8 MiB`) caps to stay well inside LocalEDR's 20 MB daemon RSS budget.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use crate::RulesError;

#[derive(Default)]
struct NrdCancelState {
    cancelled: AtomicBool,
    #[cfg(windows)]
    active_request_handle: std::sync::Mutex<Option<usize>>,
}

/// Cooperative cancellation token for [`fetch_nrd_feed_url_cancellable`] and
/// [`refresh_nrd_cache_cancellable`].
#[derive(Clone, Default)]
pub struct NrdCancelToken {
    state: Arc<NrdCancelState>,
}

impl std::fmt::Debug for NrdCancelToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NrdCancelToken")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

impl NrdCancelToken {
    /// Creates a new uncancelled [`NrdCancelToken`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if [`NrdCancelToken::cancel`] has been called.
    pub fn is_cancelled(&self) -> bool {
        self.state.cancelled.load(Ordering::Acquire)
    }

    /// Cancels any current or future NRD fetch associated with this token.
    ///
    /// On Windows, atomically takes and closes any active WinHTTP request handle so an in-flight
    /// synchronous request aborts immediately without waiting for network timeouts.
    pub fn cancel(&self) {
        self.state.cancelled.store(true, Ordering::SeqCst);
        #[cfg(windows)]
        {
            let raw_handle = {
                let mut guard = self
                    .state
                    .active_request_handle
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                guard.take()
            };
            if let Some(handle_addr) = raw_handle {
                // SAFETY: `handle_addr` was registered from `WinHttpOpenRequest` and `take()`
                // guarantees `WinHttpCloseHandle` is invoked at most once across `cancel()` and
                // `CancellableWinHttpHandle::drop()`.
                unsafe {
                    let _ = winhttp_ffi::WinHttpCloseHandle(handle_addr as *mut std::ffi::c_void);
                }
            }
        }
    }
}

static TMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Default public 14-day NRD feeds (`hagezi/nrd`, `決定記録 L-14`).
pub const DEFAULT_NRD_FEED_URLS: &[&str] = &[
    "https://raw.githubusercontent.com/hagezi/nrd/main/domains/nrd7.txt",
    "https://raw.githubusercontent.com/hagezi/nrd/main/domains/nrd14-8.txt",
];

/// Maximum number of normalized NRD domain entries kept in memory and on disk.
pub const NRD_MAX_ENTRIES: usize = 50_000;

/// Maximum response payload read per feed URL (8 MiB).
pub const NRD_MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Default refresh interval for the daily NRD feed (24 hours in milliseconds).
pub const NRD_REFRESH_INTERVAL_MS: u64 = 86_400_000;

const NRD_CACHE_HEADER: &str = "# LocalEDR NRD Cache";
const NRD_UPDATED_PREFIX: &str = "# updated_at_ms=";

/// Bounded in-memory + disk-persisted cache of newly registered domains (`L-14`).
#[derive(Debug, Clone, Default)]
pub struct NrdCache {
    domains: HashSet<String>,
    updated_at_ms: Option<i64>,
    truncated: bool,
}

/// Summary metrics produced by [`refresh_nrd_cache`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NrdRefreshStats {
    pub feeds_succeeded: usize,
    pub feeds_failed: usize,
    pub total_entries: usize,
    pub truncated: bool,
    pub errors: Vec<String>,
}

impl NrdCache {
    /// Creates a new empty [`NrdCache`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an [`NrdCache`] directly from normalized domain entries (capped at `max_entries`).
    pub fn from_domains<I, S>(domains: I, updated_at_ms: Option<i64>, max_entries: usize) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let cap = max_entries.max(1);
        let mut set = HashSet::new();
        let mut truncated = false;
        for item in domains {
            if let Some(norm) = normalize_nrd_domain(item.as_ref()) {
                if set.len() >= cap && !set.contains(&norm) {
                    truncated = true;
                    break;
                }
                set.insert(norm);
            }
        }
        Self {
            domains: set,
            updated_at_ms,
            truncated,
        }
    }

    /// Returns the number of cached NRD domains.
    pub fn len(&self) -> usize {
        self.domains.len()
    }

    /// Returns `true` when the cache contains no domains.
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    /// Returns the backing normalized lowercase domain set for [`crate::assess_domain_risk`].
    pub fn domains(&self) -> &HashSet<String> {
        &self.domains
    }

    /// Returns the Unix epoch timestamp (milliseconds) of the last successful refresh.
    pub fn updated_at_ms(&self) -> Option<i64> {
        self.updated_at_ms
    }

    /// Returns `true` if parsing or loading hit the entry or byte cap.
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Returns `true` if `updated_at_ms` is absent or older than `refresh_interval_ms`.
    pub fn is_stale(&self, now_ms: i64, refresh_interval_ms: u64) -> bool {
        let Some(updated) = self.updated_at_ms else {
            return true;
        };
        let interval = i64::try_from(refresh_interval_ms).unwrap_or(i64::MAX);
        now_ms.saturating_sub(updated) >= interval
    }

    /// Returns `true` if `domain` or any multi-label parent suffix of `domain` is in the cache.
    pub fn contains(&self, domain: &str) -> bool {
        matches_domain_or_parent_in_set(domain, &self.domains)
    }

    /// Loads an [`NrdCache`] from a local cache file, enforcing `max_entries` and
    /// [`NRD_MAX_RESPONSE_BYTES`].
    pub fn load_from_file(path: &Path, max_entries: usize) -> Result<Self, RulesError> {
        let file = File::open(path)?;
        let fallback_mtime_ms = file
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .and_then(|d| i64::try_from(d.as_millis()).ok());

        let cap = max_entries.max(1);
        let limited = file.take(NRD_MAX_RESPONSE_BYTES as u64 + 1);
        let mut reader = BufReader::new(limited);
        let mut line = String::new();
        let mut updated_at_ms = None;
        let mut domains = HashSet::new();
        let mut truncated = false;
        let mut bytes_read = 0usize;

        loop {
            line.clear();
            let n = reader.read_line(&mut line)?;
            if n == 0 {
                break;
            }
            bytes_read = bytes_read.saturating_add(n);
            if bytes_read > NRD_MAX_RESPONSE_BYTES {
                truncated = true;
                break;
            }
            let trimmed = line.trim();
            if let Some(ts_str) = trimmed.strip_prefix(NRD_UPDATED_PREFIX) {
                if let Ok(ts) = ts_str.trim().parse::<i64>() {
                    updated_at_ms = Some(ts);
                }
                continue;
            }
            if let Some(domain) = parse_nrd_line(trimmed) {
                if domains.len() >= cap && !domains.contains(&domain) {
                    truncated = true;
                    break;
                }
                domains.insert(domain);
            }
        }

        Ok(Self {
            domains,
            updated_at_ms: updated_at_ms.or(fallback_mtime_ms),
            truncated,
        })
    }

    /// Atomically persists the cache to `path` (sorted for deterministic diffs/inspection).
    pub fn save_to_file(&self, path: &Path) -> Result<(), RulesError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("nrd-cache.txt");
        let seq = TMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp_path = path.with_file_name(format!(
            "{file_name}.tmp.{}.{seq}",
            std::process::id()
        ));

        let write_res = (|| -> Result<(), std::io::Error> {
            let mut file = File::create(&tmp_path)?;
            writeln!(file, "{NRD_CACHE_HEADER}")?;
            if let Some(ts) = self.updated_at_ms {
                writeln!(file, "{NRD_UPDATED_PREFIX}{ts}")?;
            }
            let mut sorted: Vec<&str> = self.domains.iter().map(String::as_str).collect();
            sorted.sort_unstable();
            for domain in sorted {
                writeln!(file, "{domain}")?;
            }
            file.flush()?;
            Ok(())
        })();
        if let Err(err) = write_res {
            let _ = fs::remove_file(&tmp_path);
            return Err(RulesError::Io(err));
        }

        replace_file_atomically(&tmp_path, path)?;
        Ok(())
    }
}

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

/// Fetches a single NRD feed URL (`https://`, `file://`, or loopback-only `http://` for tests),
/// strictly bounding memory read to `max_bytes` (`NRD_MAX_RESPONSE_BYTES` = 8 MiB).
///
/// Unencrypted remote `http://` URLs are rejected to prevent MITM poisoning of the NRD cache.
/// Returns `(bytes, truncated)`. When `truncated` is `true`, any partial trailing line is
/// trimmed at the final newline so parsers never see half a domain name.
pub fn fetch_nrd_feed_url(url: &str, max_bytes: usize) -> Result<(Vec<u8>, bool), String> {
    fetch_nrd_feed_url_cancellable(url, max_bytes, &NrdCancelToken::new())
}

/// Cancellable variant of [`fetch_nrd_feed_url`] controlled by [`NrdCancelToken`].
pub fn fetch_nrd_feed_url_cancellable(
    url: &str,
    max_bytes: usize,
    cancel: &NrdCancelToken,
) -> Result<(Vec<u8>, bool), String> {
    if cancel.is_cancelled() {
        return Err("NRD feed download cancelled".to_string());
    }
    let trimmed = url.trim();
    if trimmed
        .get(..7)
        .is_some_and(|p| p.eq_ignore_ascii_case("file://"))
    {
        let path = parse_file_url(trimmed)?;
        let res = read_bounded_file(&path, max_bytes)?;
        if cancel.is_cancelled() {
            return Err("NRD feed download cancelled".to_string());
        }
        return Ok(res);
    }
    if trimmed
        .get(..8)
        .is_some_and(|p| p.eq_ignore_ascii_case("https://"))
        || trimmed
            .get(..7)
            .is_some_and(|p| p.eq_ignore_ascii_case("http://"))
    {
        let parsed = parse_http_url(trimmed)?;
        if !parsed.is_https && !is_loopback_http_host(&parsed.host) {
            return Err(format!(
                "refusing unencrypted remote HTTP NRD feed URL `{trimmed}` (https:// required for non-loopback hosts)"
            ));
        }
        return fetch_http_winhttp_cancellable(&parsed, max_bytes, cancel);
    }
    Err(format!(
        "unsupported NRD feed URL `{trimmed}` (expected https://, file://, or loopback http://)"
    ))
}

fn read_bounded_file(path: &Path, max_bytes: usize) -> Result<(Vec<u8>, bool), String> {
    let cap = max_bytes.max(1);
    let file = File::open(path)
        .map_err(|err| format!("failed to open NRD feed file `{}`: {err}", path.display()))?;
    let mut buf = Vec::new();
    file.take(cap as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|err| format!("failed to read NRD feed file `{}`: {err}", path.display()))?;
    let truncated = if buf.len() > cap {
        buf.truncate(cap);
        trim_partial_trailing_line(&mut buf);
        true
    } else {
        false
    };
    Ok((buf, truncated))
}

fn trim_partial_trailing_line(buf: &mut Vec<u8>) {
    if let Some(pos) = buf.iter().rposition(|&b| b == b'\n') {
        buf.truncate(pos + 1);
    } else {
        // The entire truncated buffer is an incomplete single line; discard it so parsers
        // never ingest a corrupted half-domain.
        buf.clear();
    }
}

/// Reads chunks from a streaming source via `next_chunk(max_to_read)` until EOF (`Ok(None)`) or
/// `max_bytes` is exceeded. When truncated, trims any partial trailing line (clearing the buffer
/// if no newline was seen) so NRD parsers never ingest a half-domain.
#[cfg(test)]
pub(crate) fn read_bounded_chunks<F>(
    max_bytes: usize,
    next_chunk: F,
) -> Result<(Vec<u8>, bool), String>
where
    F: FnMut(usize) -> Result<Option<Vec<u8>>, String>,
{
    read_bounded_chunks_cancellable(max_bytes, &NrdCancelToken::new(), next_chunk)
}

/// Cancellable variant of [`read_bounded_chunks`].
pub(crate) fn read_bounded_chunks_cancellable<F>(
    max_bytes: usize,
    cancel: &NrdCancelToken,
    mut next_chunk: F,
) -> Result<(Vec<u8>, bool), String>
where
    F: FnMut(usize) -> Result<Option<Vec<u8>>, String>,
{
    let cap = max_bytes.max(1);
    let mut body = Vec::new();
    let mut truncated = false;

    loop {
        if cancel.is_cancelled() {
            return Err("NRD feed download cancelled".to_string());
        }
        let remaining_budget = cap.saturating_sub(body.len());
        let want = if remaining_budget == 0 {
            1
        } else {
            remaining_budget.saturating_add(1).min(16_384)
        };
        let Some(chunk) = next_chunk(want)? else {
            break;
        };
        if cancel.is_cancelled() {
            return Err("NRD feed download cancelled".to_string());
        }
        if chunk.is_empty() {
            break;
        }
        if remaining_budget == 0 {
            trim_partial_trailing_line(&mut body);
            truncated = true;
            break;
        }
        if body.len().saturating_add(chunk.len()) > cap {
            let take = cap.saturating_sub(body.len());
            body.extend_from_slice(&chunk[..take]);
            trim_partial_trailing_line(&mut body);
            truncated = true;
            break;
        }
        body.extend_from_slice(&chunk);
    }

    Ok((body, truncated))
}

/// Refreshes the NRD cache from all URLs in `feed_urls`, enforcing `max_entries` and
/// `max_bytes_per_feed`. Succeeds if at least one feed succeeds; fails if all feeds fail so
/// callers retain any previously valid cache instead of clearing it.
pub fn refresh_nrd_cache(
    feed_urls: &[String],
    max_entries: usize,
    max_bytes_per_feed: usize,
    now_ms: i64,
) -> Result<(NrdCache, NrdRefreshStats), String> {
    refresh_nrd_cache_cancellable(
        feed_urls,
        max_entries,
        max_bytes_per_feed,
        now_ms,
        &NrdCancelToken::new(),
    )
}

/// Cancellable variant of [`refresh_nrd_cache`] controlled by [`NrdCancelToken`].
pub fn refresh_nrd_cache_cancellable(
    feed_urls: &[String],
    max_entries: usize,
    max_bytes_per_feed: usize,
    now_ms: i64,
    cancel: &NrdCancelToken,
) -> Result<(NrdCache, NrdRefreshStats), String> {
    if cancel.is_cancelled() {
        return Err("NRD feed refresh cancelled".to_string());
    }
    if feed_urls.is_empty() {
        return Err("no NRD feed URLs configured".to_string());
    }

    let cap = max_entries.max(1);
    let mut merged = HashSet::new();
    let mut stats = NrdRefreshStats::default();

    for url in feed_urls {
        if cancel.is_cancelled() {
            return Err("NRD feed refresh cancelled".to_string());
        }
        match fetch_nrd_feed_url_cancellable(url, max_bytes_per_feed, cancel) {
            Ok((bytes, byte_truncated)) => {
                stats.feeds_succeeded += 1;
                let (_, entry_truncated) = parse_nrd_feed_bytes(&bytes, &mut merged, cap);
                if byte_truncated || entry_truncated {
                    stats.truncated = true;
                }
            }
            Err(err) => {
                if cancel.is_cancelled() {
                    return Err("NRD feed refresh cancelled".to_string());
                }
                stats.feeds_failed += 1;
                stats.errors.push(format!("{url}: {err}"));
            }
        }
    }

    if cancel.is_cancelled() {
        return Err("NRD feed refresh cancelled".to_string());
    }

    if stats.feeds_succeeded == 0 {
        return Err(format!(
            "all {} NRD feed(s) failed: {}",
            feed_urls.len(),
            stats.errors.join("; ")
        ));
    }

    stats.total_entries = merged.len();
    let cache = NrdCache {
        domains: merged,
        updated_at_ms: Some(now_ms),
        truncated: stats.truncated,
    };
    Ok((cache, stats))
}

#[cfg(windows)]
fn replace_file_atomically(tmp_path: &Path, dest_path: &Path) -> Result<(), std::io::Error> {
    use std::os::windows::ffi::OsStrExt;
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;

    #[link(name = "kernel32.dll", kind = "raw-dylib", modifiers = "+verbatim")]
    extern "system" {
        fn MoveFileExW(
            lp_existing_file_name: *const u16,
            lp_new_file_name: *const u16,
            dw_flags: u32,
        ) -> i32;
    }

    let src_w: Vec<u16> = tmp_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let dst_w: Vec<u16> = dest_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: `src_w` and `dst_w` are valid NUL-terminated UTF-16 paths.
    let ok = unsafe {
        MoveFileExW(
            src_w.as_ptr(),
            dst_w.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        let err = std::io::Error::last_os_error();
        let _ = fs::remove_file(tmp_path);
        return Err(err);
    }
    Ok(())
}

#[cfg(not(windows))]
fn replace_file_atomically(tmp_path: &Path, dest_path: &Path) -> Result<(), std::io::Error> {
    fs::rename(tmp_path, dest_path)
}

#[cfg(windows)]
mod winhttp_ffi {
    use std::ffi::c_void;

    pub const WINHTTP_ACCESS_TYPE_DEFAULT_PROXY: u32 = 0;
    pub const WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY: u32 = 4;
    pub const WINHTTP_FLAG_SECURE: u32 = 0x0080_0000;
    pub const WINHTTP_QUERY_STATUS_CODE: u32 = 19;
    pub const WINHTTP_QUERY_FLAG_NUMBER: u32 = 0x2000_0000;

    #[link(name = "winhttp.dll", kind = "raw-dylib", modifiers = "+verbatim")]
    extern "system" {
        pub fn WinHttpOpen(
            psz_agent_w: *const u16,
            dw_access_type: u32,
            psz_proxy_w: *const u16,
            psz_proxy_bypass_w: *const u16,
            dw_flags: u32,
        ) -> *mut c_void;
        pub fn WinHttpSetTimeouts(
            h_internet: *mut c_void,
            n_resolve_timeout: i32,
            n_connect_timeout: i32,
            n_send_timeout: i32,
            n_receive_timeout: i32,
        ) -> i32;
        pub fn WinHttpConnect(
            h_session: *mut c_void,
            pswz_server_name: *const u16,
            n_server_port: u16,
            dw_reserved: u32,
        ) -> *mut c_void;
        pub fn WinHttpOpenRequest(
            h_connect: *mut c_void,
            pwsz_verb: *const u16,
            pwsz_object_name: *const u16,
            pwsz_version: *const u16,
            pwsz_referrer: *const u16,
            ppwsz_accept_types: *const *const u16,
            dw_flags: u32,
        ) -> *mut c_void;
        pub fn WinHttpSendRequest(
            h_request: *mut c_void,
            lpsz_headers: *const u16,
            dw_headers_length: u32,
            lp_optional: *mut c_void,
            dw_optional_length: u32,
            dw_total_length: u32,
            dw_context: usize,
        ) -> i32;
        pub fn WinHttpReceiveResponse(h_request: *mut c_void, lp_reserved: *mut c_void) -> i32;
        pub fn WinHttpQueryHeaders(
            h_request: *mut c_void,
            dw_info_level: u32,
            pwsz_name: *const u16,
            lp_buffer: *mut c_void,
            lpdw_buffer_length: *mut u32,
            lpdw_index: *mut u32,
        ) -> i32;
        pub fn WinHttpQueryDataAvailable(
            h_request: *mut c_void,
            lpdw_number_of_bytes_available: *mut u32,
        ) -> i32;
        pub fn WinHttpReadData(
            h_request: *mut c_void,
            lp_buffer: *mut c_void,
            dw_number_of_bytes_to_read: u32,
            lpdw_number_of_bytes_read: *mut u32,
        ) -> i32;
        pub fn WinHttpCloseHandle(h_internet: *mut c_void) -> i32;
    }
}

#[cfg(windows)]
fn fetch_http_winhttp_cancellable(
    parsed: &ParsedHttpUrl,
    max_bytes: usize,
    cancel: &NrdCancelToken,
) -> Result<(Vec<u8>, bool), String> {
    use std::ffi::c_void;
    use std::ptr;
    use winhttp_ffi::*;

    struct OwnedWinHttpHandle(*mut c_void);
    impl Drop for OwnedWinHttpHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` was opened by WinHTTP and is closed exactly once.
                unsafe {
                    let _ = WinHttpCloseHandle(self.0);
                }
                self.0 = ptr::null_mut();
            }
        }
    }

    // RAII guard for the cancellable request handle: `take()`s from `active_request_handle`
    // before closing so `NrdCancelToken::cancel()` and `Drop` NEVER double-close the same
    // HINTERNET handle (`BUG_0005`).
    struct CancellableWinHttpHandle<'a> {
        cancel: &'a NrdCancelToken,
        raw: *mut c_void,
    }

    impl<'a> CancellableWinHttpHandle<'a> {
        fn register(cancel: &'a NrdCancelToken, raw_request: *mut c_void) -> Result<Self, String> {
            let mut guard = cancel
                .state
                .active_request_handle
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if cancel.state.cancelled.load(Ordering::SeqCst) {
                drop(guard);
                // SAFETY: `raw_request` was opened by `WinHttpOpenRequest` and never published.
                unsafe {
                    let _ = WinHttpCloseHandle(raw_request);
                }
                return Err("NRD feed download cancelled".to_string());
            }
            *guard = Some(raw_request as usize);
            Ok(Self {
                cancel,
                raw: raw_request,
            })
        }

        fn raw(&self) -> *mut c_void {
            self.raw
        }
    }

    impl Drop for CancellableWinHttpHandle<'_> {
        fn drop(&mut self) {
            let raw_handle = {
                let mut guard = self
                    .cancel
                    .state
                    .active_request_handle
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                guard.take()
            };
            if let Some(handle_addr) = raw_handle {
                // SAFETY: `take()` ensures `WinHttpCloseHandle` is called at most once
                // between `NrdCancelToken::cancel()` and `CancellableWinHttpHandle::drop()`.
                unsafe {
                    let _ = WinHttpCloseHandle(handle_addr as *mut c_void);
                }
            }
        }
    }

    if cancel.is_cancelled() {
        return Err("NRD feed download cancelled".to_string());
    }

    let to_wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
    let agent_w = to_wide("LocalEDR/0.1 (NRD Feed Sync)");
    let host_w = to_wide(&parsed.host);
    let verb_w = to_wide("GET");
    let path_w = to_wide(&parsed.path_and_query);

    // SAFETY: All pointers are NUL-terminated UTF-16 or NULL; returned handles use RAII guards.
    let raw_session = unsafe {
        let h = WinHttpOpen(
            agent_w.as_ptr(),
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            ptr::null(),
            ptr::null(),
            0,
        );
        if h.is_null() {
            WinHttpOpen(
                agent_w.as_ptr(),
                WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                ptr::null(),
                ptr::null(),
                0,
            )
        } else {
            h
        }
    };
    if raw_session.is_null() {
        return Err(format!(
            "WinHttpOpen failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let session = OwnedWinHttpHandle(raw_session);

    // Bounded network timeouts: 10s resolve/connect/send, 20s receive.
    // SAFETY: `session.0` is an open WinHTTP session handle.
    unsafe {
        let _ = WinHttpSetTimeouts(session.0, 10_000, 10_000, 10_000, 20_000);
    }

    if cancel.is_cancelled() {
        return Err("NRD feed download cancelled".to_string());
    }

    // SAFETY: `session.0` is valid and `host_w` is NUL-terminated UTF-16.
    let raw_connect = unsafe { WinHttpConnect(session.0, host_w.as_ptr(), parsed.port, 0) };
    if raw_connect.is_null() {
        if cancel.is_cancelled() {
            return Err("NRD feed download cancelled".to_string());
        }
        return Err(format!(
            "WinHttpConnect(`{}:{}`) failed: {}",
            parsed.host,
            parsed.port,
            std::io::Error::last_os_error()
        ));
    }
    let connect = OwnedWinHttpHandle(raw_connect);

    if cancel.is_cancelled() {
        return Err("NRD feed download cancelled".to_string());
    }

    let flags = if parsed.is_https {
        WINHTTP_FLAG_SECURE
    } else {
        0
    };
    // SAFETY: `connect.0` is valid and UTF-16 strings are NUL-terminated.
    let raw_request = unsafe {
        WinHttpOpenRequest(
            connect.0,
            verb_w.as_ptr(),
            path_w.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            flags,
        )
    };
    if raw_request.is_null() {
        if cancel.is_cancelled() {
            return Err("NRD feed download cancelled".to_string());
        }
        return Err(format!(
            "WinHttpOpenRequest(`{}`) failed: {}",
            parsed.path_and_query,
            std::io::Error::last_os_error()
        ));
    }
    let request = CancellableWinHttpHandle::register(cancel, raw_request)?;

    if cancel.is_cancelled() {
        return Err("NRD feed download cancelled".to_string());
    }

    // SAFETY: `request.raw()` is a valid WinHTTP request handle.
    let send_ok = unsafe {
        WinHttpSendRequest(request.raw(), ptr::null(), 0, ptr::null_mut(), 0, 0, 0)
    };
    if send_ok == 0 {
        if cancel.is_cancelled() {
            return Err("NRD feed download cancelled".to_string());
        }
        return Err(format!(
            "WinHttpSendRequest failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    if cancel.is_cancelled() {
        return Err("NRD feed download cancelled".to_string());
    }

    // SAFETY: `request.raw()` has a sent HTTP request.
    let recv_ok = unsafe { WinHttpReceiveResponse(request.raw(), ptr::null_mut()) };
    if recv_ok == 0 {
        if cancel.is_cancelled() {
            return Err("NRD feed download cancelled".to_string());
        }
        return Err(format!(
            "WinHttpReceiveResponse failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    if cancel.is_cancelled() {
        return Err("NRD feed download cancelled".to_string());
    }

    let mut status_code: u32 = 0;
    let mut status_len = std::mem::size_of::<u32>() as u32;
    // SAFETY: Queries HTTP status code into `status_code` (`DWORD`).
    let hdr_ok = unsafe {
        WinHttpQueryHeaders(
            request.raw(),
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            ptr::null(),
            (&mut status_code as *mut u32).cast::<c_void>(),
            &mut status_len,
            ptr::null_mut(),
        )
    };
    if hdr_ok == 0 {
        if cancel.is_cancelled() {
            return Err("NRD feed download cancelled".to_string());
        }
        return Err(format!(
            "WinHttpQueryHeaders(STATUS_CODE) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if !(200..300).contains(&status_code) {
        return Err(format!("HTTP status {status_code}"));
    }

    read_bounded_chunks_cancellable(max_bytes, cancel, |want| {
        if cancel.is_cancelled() {
            return Err("NRD feed download cancelled".to_string());
        }
        let mut avail: u32 = 0;
        // SAFETY: `request.raw()` has received response headers.
        let avail_ok = unsafe { WinHttpQueryDataAvailable(request.raw(), &mut avail) };
        if avail_ok == 0 {
            if cancel.is_cancelled() {
                return Err("NRD feed download cancelled".to_string());
            }
            return Err(format!(
                "WinHttpQueryDataAvailable failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        if avail == 0 {
            return Ok(None);
        }
        if cancel.is_cancelled() {
            return Err("NRD feed download cancelled".to_string());
        }

        let to_read = (avail as usize).min(want).max(1);
        let mut chunk = vec![0u8; to_read];
        let mut read_len: u32 = 0;
        // SAFETY: `chunk` has length `to_read`.
        let read_ok = unsafe {
            WinHttpReadData(
                request.raw(),
                chunk.as_mut_ptr().cast::<c_void>(),
                to_read as u32,
                &mut read_len,
            )
        };
        if read_ok == 0 {
            if cancel.is_cancelled() {
                return Err("NRD feed download cancelled".to_string());
            }
            return Err(format!(
                "WinHttpReadData failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        if read_len == 0 {
            return Ok(None);
        }
        chunk.truncate((read_len as usize).min(to_read));
        Ok(Some(chunk))
    })
}

#[cfg(not(windows))]
fn fetch_http_winhttp_cancellable(
    _parsed: &ParsedHttpUrl,
    _max_bytes: usize,
    cancel: &NrdCancelToken,
) -> Result<(Vec<u8>, bool), String> {
    if cancel.is_cancelled() {
        return Err("NRD feed download cancelled".to_string());
    }
    Err("WinHTTP NRD feed fetch is only supported on Windows".to_string())
}
