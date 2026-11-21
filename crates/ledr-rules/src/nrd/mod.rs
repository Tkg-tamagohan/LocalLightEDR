//! Daily Newly Registered Domain (NRD) feed fetcher and bounded local cache (`決定記録 L-14`).
//!
//! Fetches public 14-day NRD feeds (`hagezi/nrd` `nrd7.txt` + `nrd14-8.txt` by default) via
//! Windows built-in `winhttp.dll` (`raw-dylib`, zero external HTTP crate dependencies) or local
//! `file://` URLs for deterministic offline tests. Enforces strict entry (`50,000`) and response
//! byte (`8 MiB`) caps to stay well inside LocalEDR's 20 MB daemon RSS budget.

mod cache;
mod cancel;
mod parser;
mod reader;
mod url;
mod winhttp;
#[cfg(windows)]
mod winhttp_ctx;
#[cfg(windows)]
mod winhttp_ffi;

use cache::{FlatDomainSet, InsertOutcome};
use parser::parse_nrd_line_into;
use winhttp::fetch_http_winhttp_cancellable;

pub use cache::{NrdCache, NrdRefreshStats};
pub use cancel::NrdCancelToken;
pub(crate) use parser::matches_domain_or_parent_in_set;
pub use parser::{normalize_nrd_domain, parse_nrd_feed_bytes, parse_nrd_line};
#[cfg(test)]
pub(crate) use reader::{
    read_bounded_chunks_cancellable, read_bounded_reader_cancellable, NRD_FILE_READ_CHUNK_BYTES,
};
pub(crate) use reader::read_bounded_file;
pub(crate) use url::is_loopback_http_host;
pub use url::{parse_file_url, parse_http_url, ParsedHttpUrl};

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
        let res = read_bounded_file(&path, max_bytes, cancel)?;
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
    let mut merged = FlatDomainSet::new();
    let mut norm_buf = String::new();
    let mut stats = NrdRefreshStats::default();

    for url in feed_urls {
        if cancel.is_cancelled() {
            return Err("NRD feed refresh cancelled".to_string());
        }
        match fetch_nrd_feed_url_cancellable(url, max_bytes_per_feed, cancel) {
            Ok((bytes, byte_truncated)) => {
                stats.feeds_succeeded += 1;
                let text = String::from_utf8_lossy(&bytes);
                let mut entry_truncated = false;
                for line in text.lines() {
                    if parse_nrd_line_into(line, &mut norm_buf)
                        && merged.insert_bounded(&norm_buf, cap) == InsertOutcome::CapReached
                    {
                        entry_truncated = true;
                        break;
                    }
                }
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
    let cache = merged.into_nrd_cache(Some(now_ms), stats.truncated);
    Ok((cache, stats))
}
