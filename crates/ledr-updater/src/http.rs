//! Independent bounded WinHTTP release client (`winhttp.dll` `raw-dylib`)
//! with manual HTTPS-only redirect verification and instant `Condvar` cancellation.

use std::io::{BufWriter, Write};
use std::net::IpAddr;
use std::path::Path;

use crate::{
    fs_safe, CancelToken, DownloadProgress, HttpClientConfig, UpdaterError, ALLOWED_DOWNLOAD_HOSTS,
    LATEST_MANIFEST_URL, LATEST_SIG_URL, MAX_INSTALLER_BYTES, MAX_MANIFEST_BYTES, MAX_SIG_BYTES,
    RELEASE_URL_PREFIX,
};

#[cfg(windows)]
pub(crate) use windows_impl::AsyncWinHttpContext;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedHttpUrl {
    pub(crate) is_https: bool,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) path_and_query: String,
}

pub(crate) fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
    }
}

pub(crate) fn is_loopback_host(host: &str) -> bool {
    let norm = host.trim().trim_end_matches('.');
    if norm.eq_ignore_ascii_case("localhost") {
        return true;
    }
    norm.parse::<IpAddr>()
        .is_ok_and(|ip| match canonical_ip(ip) {
            IpAddr::V4(v4) => v4.is_loopback(),
            IpAddr::V6(v6) => v6.is_loopback(),
        })
}

pub(crate) fn parse_http_url(url: &str) -> Result<ParsedHttpUrl, UpdaterError> {
    if url.is_empty()
        || url
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return Err(UpdaterError::UnsafeUrl(format!(
            "URL {url:?} is empty or contains whitespace/control characters"
        )));
    }

    let (is_https, rest_with_frag) = if url
        .get(..8)
        .is_some_and(|p| p.eq_ignore_ascii_case("https://"))
    {
        (true, &url[8..])
    } else if url
        .get(..7)
        .is_some_and(|p| p.eq_ignore_ascii_case("http://"))
    {
        (false, &url[7..])
    } else {
        return Err(UpdaterError::UnsafeUrl(format!(
            "unsupported URL scheme in {url:?}"
        )));
    };

    let rest = rest_with_frag.split('#').next().unwrap_or(rest_with_frag);
    if rest.is_empty() {
        return Err(UpdaterError::UnsafeUrl(format!(
            "missing host in URL {url:?}"
        )));
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
        return Err(UpdaterError::UnsafeUrl(format!(
            "invalid or userinfo-bearing authority in URL {url:?}"
        )));
    }

    // Reject path traversal segments and backslashes in URL path component.
    let path_only = path_and_query.split('?').next().unwrap_or(&path_and_query);
    if path_only.contains('\\') {
        return Err(UpdaterError::UnsafeUrl(format!(
            "backslash in URL path rejected: {url:?}"
        )));
    }
    let path_lower = path_only.to_ascii_lowercase();
    if path_lower.contains("%2e") || path_lower.contains("%2f") || path_lower.contains("%5c") {
        return Err(UpdaterError::UnsafeUrl(format!(
            "percent-encoded traversal/separator in URL path rejected: {url:?}"
        )));
    }
    for seg in path_only.split('/') {
        if seg == "." || seg == ".." {
            return Err(UpdaterError::UnsafeUrl(format!(
                "dot-segment traversal in URL path rejected: {url:?}"
            )));
        }
    }

    let default_port = if is_https { 443 } else { 80 };
    let (host, port) = if let Some(bracket_rest) = authority.strip_prefix('[') {
        let end = bracket_rest.find(']').ok_or_else(|| {
            UpdaterError::UnsafeUrl(format!("unclosed IPv6 host bracket in URL {url:?}"))
        })?;
        let host_str = &bracket_rest[..end];
        let after = &bracket_rest[end + 1..];
        let port = if after.is_empty() {
            default_port
        } else if let Some(port_str) = after.strip_prefix(':') {
            parse_nonzero_port(port_str, url)?
        } else {
            return Err(UpdaterError::UnsafeUrl(format!(
                "unexpected trailing authority syntax in URL {url:?}"
            )));
        };
        (host_str.to_string(), port)
    } else if let Some((h, port_str)) = authority.rsplit_once(':') {
        let port = parse_nonzero_port(port_str, url)?;
        (h.to_string(), port)
    } else {
        (authority.to_string(), default_port)
    };

    if host.is_empty() {
        return Err(UpdaterError::UnsafeUrl(format!(
            "empty host in URL {url:?}"
        )));
    }

    Ok(ParsedHttpUrl {
        is_https,
        host,
        port,
        path_and_query,
    })
}

fn parse_nonzero_port(port_str: &str, url: &str) -> Result<u16, UpdaterError> {
    if port_str.is_empty() || !port_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(UpdaterError::UnsafeUrl(format!(
            "invalid port {port_str:?} in URL {url:?}"
        )));
    }
    let port = port_str
        .parse::<u16>()
        .map_err(|_| UpdaterError::UnsafeUrl(format!("invalid port {port_str:?} in URL {url:?}")))?;
    if port == 0 {
        return Err(UpdaterError::UnsafeUrl(format!(
            "port 0 is not allowed in URL {url:?}"
        )));
    }
    Ok(port)
}

/// Validates an initial manifest/signature URL against [`RELEASE_URL_PREFIX`].
pub(crate) fn validate_initial_release_url(
    url: &str,
    allow_loopback_http_for_tests: bool,
) -> Result<(), UpdaterError> {
    let parsed = parse_http_url(url)?;
    if allow_loopback_http_for_tests && !parsed.is_https && is_loopback_host(&parsed.host) {
        return Ok(());
    }
    if !parsed.is_https {
        return Err(UpdaterError::UnsafeUrl(format!(
            "initial release URL must use HTTPS: {url}"
        )));
    }
    if parsed.port != 443 || !parsed.host.eq_ignore_ascii_case("github.com") {
        return Err(UpdaterError::UnsafeUrl(format!(
            "initial release URL must target github.com:443: {url}"
        )));
    }
    if !url.starts_with(RELEASE_URL_PREFIX) {
        return Err(UpdaterError::UnsafeUrl(format!(
            "initial release URL must start with {RELEASE_URL_PREFIX}: {url}"
        )));
    }
    Ok(())
}

/// Validates a redirect target or asset download URL against HTTPS and [`ALLOWED_DOWNLOAD_HOSTS`].
pub(crate) fn validate_download_url(
    url: &str,
    allow_loopback_http_for_tests: bool,
) -> Result<(), UpdaterError> {
    let parsed = parse_http_url(url)?;
    if allow_loopback_http_for_tests && !parsed.is_https && is_loopback_host(&parsed.host) {
        return Ok(());
    }
    if !parsed.is_https {
        return Err(UpdaterError::UnsafeUrl(format!(
            "download URL must use HTTPS: {url}"
        )));
    }
    if parsed.port != 443 {
        return Err(UpdaterError::UnsafeUrl(format!(
            "download URL must use standard HTTPS port 443: {url}"
        )));
    }
    if !ALLOWED_DOWNLOAD_HOSTS
        .iter()
        .any(|allowed| parsed.host.eq_ignore_ascii_case(allowed))
    {
        return Err(UpdaterError::UnsafeUrl(format!(
            "download host {:?} is not in ALLOWED_DOWNLOAD_HOSTS",
            parsed.host
        )));
    }
    Ok(())
}

fn format_origin(parsed: &ParsedHttpUrl) -> String {
    let scheme = if parsed.is_https { "https" } else { "http" };
    let host_fmt = if parsed.host.contains(':') {
        format!("[{}]", parsed.host)
    } else {
        parsed.host.clone()
    };
    let is_default_port =
        (parsed.is_https && parsed.port == 443) || (!parsed.is_https && parsed.port == 80);
    if is_default_port {
        format!("{scheme}://{host_fmt}")
    } else {
        format!("{scheme}://{host_fmt}:{}", parsed.port)
    }
}

pub(crate) fn resolve_redirect_location(
    current: &ParsedHttpUrl,
    raw_location: &str,
) -> Result<String, UpdaterError> {
    let loc = raw_location.trim();
    if loc.is_empty()
        || loc
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return Err(UpdaterError::UnsafeUrl(format!(
            "invalid redirect Location header {raw_location:?}"
        )));
    }

    if loc
        .get(..8)
        .is_some_and(|p| p.eq_ignore_ascii_case("https://"))
    {
        return Ok(loc.to_string());
    }
    if loc
        .get(..7)
        .is_some_and(|p| p.eq_ignore_ascii_case("http://"))
    {
        if current.is_https {
            return Err(UpdaterError::UnsafeUrl(
                "HTTPS-to-HTTP redirect downgrade is forbidden".to_string(),
            ));
        }
        return Ok(loc.to_string());
    }
    if loc.starts_with("//") {
        let scheme = if current.is_https { "https:" } else { "http:" };
        return Ok(format!("{scheme}{loc}"));
    }
    let origin = format_origin(current);
    if loc.starts_with('/') {
        return Ok(format!("{origin}{loc}"));
    }
    if loc.starts_with('?') {
        let current_path = current
            .path_and_query
            .split('?')
            .next()
            .unwrap_or(&current.path_and_query);
        return Ok(format!("{origin}{current_path}{loc}"));
    }
    let current_path = current
        .path_and_query
        .split('?')
        .next()
        .unwrap_or(&current.path_and_query);
    let dir = match current_path.rfind('/') {
        Some(idx) => &current_path[..=idx],
        None => "/",
    };
    Ok(format!("{origin}{dir}{loc}"))
}

pub(crate) fn fetch_manifest(
    config: &HttpClientConfig,
    url: &str,
    cancel: &CancelToken,
) -> Result<Vec<u8>, UpdaterError> {
    validate_initial_release_url(url, config.allow_loopback_http_for_tests)?;
    let mut out = Vec::new();
    let mut noop_progress = |_| {};
    let _ = windows_impl::download_bounded(
        config,
        url,
        MAX_MANIFEST_BYTES as u64,
        "manifest",
        None,
        &mut out,
        cancel,
        &mut noop_progress,
    )?;
    Ok(out)
}

pub(crate) fn fetch_signature(
    config: &HttpClientConfig,
    url: &str,
    cancel: &CancelToken,
) -> Result<Vec<u8>, UpdaterError> {
    validate_initial_release_url(url, config.allow_loopback_http_for_tests)?;
    let mut out = Vec::new();
    let mut noop_progress = |_| {};
    let _ = windows_impl::download_bounded(
        config,
        url,
        MAX_SIG_BYTES as u64,
        "signature",
        None,
        &mut out,
        cancel,
        &mut noop_progress,
    )?;
    Ok(out)
}

pub(crate) fn fetch_latest_manifest_and_sig(
    config: &HttpClientConfig,
    cancel: &CancelToken,
) -> Result<(Vec<u8>, Vec<u8>), UpdaterError> {
    let manifest = fetch_manifest(config, LATEST_MANIFEST_URL, cancel)?;
    let sig = fetch_signature(config, LATEST_SIG_URL, cancel)?;
    Ok((manifest, sig))
}

pub(crate) fn download_to_writer(
    config: &HttpClientConfig,
    url: &str,
    max_bytes: u64,
    writer: &mut dyn Write,
    cancel: &CancelToken,
    on_progress: &mut dyn FnMut(DownloadProgress),
) -> Result<u64, UpdaterError> {
    validate_download_url(url, config.allow_loopback_http_for_tests)?;
    windows_impl::download_bounded(
        config,
        url,
        max_bytes,
        "download",
        None,
        writer,
        cancel,
        on_progress,
    )
}

pub(crate) fn download_installer_to_file(
    config: &HttpClientConfig,
    url: &str,
    expected_size_bytes: Option<u64>,
    dest_path: &Path,
    cancel: &CancelToken,
    on_progress: &mut dyn FnMut(DownloadProgress),
) -> Result<u64, UpdaterError> {
    validate_download_url(url, config.allow_loopback_http_for_tests)?;
    if cancel.is_cancelled() {
        return Err(UpdaterError::Cancelled);
    }
    if let Some(exp) = expected_size_bytes {
        if exp == 0 {
            return Err(UpdaterError::InvalidManifest(
                "expected_size_bytes must be greater than 0".to_string(),
            ));
        }
        if exp > MAX_INSTALLER_BYTES {
            return Err(UpdaterError::ResponseTooLarge {
                kind: "installer",
                limit_bytes: MAX_INSTALLER_BYTES as usize,
                actual_bytes: exp.min(usize::MAX as u64) as usize,
            });
        }
    }

    let file = fs_safe::create_exclusive_file(dest_path)?;
    let mut writer = BufWriter::new(file);

    let result = (|| -> Result<u64, UpdaterError> {
        let written = windows_impl::download_bounded(
            config,
            url,
            MAX_INSTALLER_BYTES,
            "installer",
            expected_size_bytes,
            &mut writer,
            cancel,
            on_progress,
        )?;
        writer.flush()?;
        let inner_file = writer
            .into_inner()
            .map_err(|err| UpdaterError::Io(err.into_error()))?;
        inner_file.sync_all()?;
        if let Some(exp) = expected_size_bytes {
            if written != exp {
                return Err(UpdaterError::SizeMismatch {
                    expected: exp,
                    actual: written,
                });
            }
        }
        Ok(written)
    })();

    if result.is_err() {
        // Ensure `writer` (if still alive on early error) is dropped before deleting on Windows.
        let _ = std::fs::remove_file(dest_path);
    }
    result
}

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use std::ffi::c_void;
    use std::ptr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::{
        GetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, FALSE,
    };

    const WINHTTP_ACCESS_TYPE_DEFAULT_PROXY: u32 = 0;
    const WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY: u32 = 4;
    const WINHTTP_FLAG_SECURE: u32 = 0x0080_0000;
    const WINHTTP_FLAG_ASYNC: u32 = 0x1000_0000;

    const WINHTTP_OPTION_CONTEXT_VALUE: u32 = 45;
    const WINHTTP_OPTION_SECURE_PROTOCOLS: u32 = 84;
    const WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2: u32 = 0x0000_0800;
    const WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3: u32 = 0x0000_2000;

    const WINHTTP_OPTION_REDIRECT_POLICY: u32 = 88;
    const WINHTTP_OPTION_REDIRECT_POLICY_NEVER: u32 = 0;

    const WINHTTP_QUERY_CONTENT_LENGTH: u32 = 5;
    const WINHTTP_QUERY_STATUS_CODE: u32 = 19;
    const WINHTTP_QUERY_LOCATION: u32 = 33;
    const WINHTTP_QUERY_FLAG_NUMBER: u32 = 0x2000_0000;

    const ERROR_WINHTTP_HEADER_NOT_FOUND: u32 = 12150;

    const WINHTTP_CALLBACK_FLAG_ALL_NOTIFICATIONS: u32 = 0xFFFF_FFFF;
    const WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING: u32 = 0x0000_0800;
    const WINHTTP_CALLBACK_STATUS_SECURE_FAILURE: u32 = 0x0001_0000;
    const WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE: u32 = 0x0002_0000;
    const WINHTTP_CALLBACK_STATUS_DATA_AVAILABLE: u32 = 0x0004_0000;
    const WINHTTP_CALLBACK_STATUS_READ_COMPLETE: u32 = 0x0008_0000;
    const WINHTTP_CALLBACK_STATUS_REQUEST_ERROR: u32 = 0x0020_0000;
    const WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE: u32 = 0x0040_0000;

    const READ_CHUNK_BYTES: usize = 64 * 1024;

    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    struct WinHttpAsyncResult {
        dw_result: usize,
        dw_error: u32,
    }

    type WinHttpStatusCallback = Option<
        unsafe extern "system" fn(
            h_internet: *mut c_void,
            dw_context: usize,
            dw_internet_status: u32,
            lpv_status_information: *mut c_void,
            dw_status_information_length: u32,
        ),
    >;

    #[link(name = "winhttp.dll", kind = "raw-dylib", modifiers = "+verbatim")]
    extern "system" {
        fn WinHttpOpen(
            psz_agent_w: *const u16,
            dw_access_type: u32,
            psz_proxy_w: *const u16,
            psz_proxy_bypass_w: *const u16,
            dw_flags: u32,
        ) -> *mut c_void;
        fn WinHttpSetTimeouts(
            h_internet: *mut c_void,
            n_resolve_timeout: i32,
            n_connect_timeout: i32,
            n_send_timeout: i32,
            n_receive_timeout: i32,
        ) -> i32;
        fn WinHttpConnect(
            h_session: *mut c_void,
            pswz_server_name: *const u16,
            n_server_port: u16,
            dw_reserved: u32,
        ) -> *mut c_void;
        fn WinHttpOpenRequest(
            h_connect: *mut c_void,
            pwsz_verb: *const u16,
            pwsz_object_name: *const u16,
            pwsz_version: *const u16,
            pwsz_referrer: *const u16,
            ppwsz_accept_types: *const *const u16,
            dw_flags: u32,
        ) -> *mut c_void;
        fn WinHttpSetOption(
            h_internet: *mut c_void,
            dw_option: u32,
            lp_buffer: *const c_void,
            dw_buffer_length: u32,
        ) -> i32;
        fn WinHttpSetStatusCallback(
            h_internet: *mut c_void,
            lpfn_internet_callback: WinHttpStatusCallback,
            dw_notification_flags: u32,
            dw_reserved: usize,
        ) -> *mut c_void;
        fn WinHttpSendRequest(
            h_request: *mut c_void,
            lpsz_headers: *const u16,
            dw_headers_length: u32,
            lp_optional: *mut c_void,
            dw_optional_length: u32,
            dw_total_length: u32,
            dw_context: usize,
        ) -> i32;
        fn WinHttpReceiveResponse(h_request: *mut c_void, lp_reserved: *mut c_void) -> i32;
        fn WinHttpQueryHeaders(
            h_request: *mut c_void,
            dw_info_level: u32,
            pwsz_name: *const u16,
            lp_buffer: *mut c_void,
            lpdw_buffer_length: *mut u32,
            lpdw_index: *mut u32,
        ) -> i32;
        fn WinHttpQueryDataAvailable(
            h_request: *mut c_void,
            lpdw_number_of_bytes_available: *mut u32,
        ) -> i32;
        fn WinHttpReadData(
            h_request: *mut c_void,
            lp_buffer: *mut c_void,
            dw_number_of_bytes_to_read: u32,
            lpdw_number_of_bytes_read: *mut u32,
        ) -> i32;
        fn WinHttpCloseHandle(h_internet: *mut c_void) -> i32;
    }

    #[derive(Debug)]
    enum AsyncWaitOutcome {
        Pending,
        SendRequestComplete,
        HeadersAvailable,
        DataAvailable(u32),
        ReadComplete(u32),
        Error(String),
        Cancelled,
    }

    struct AsyncWinHttpState {
        outcome: AsyncWaitOutcome,
        last_secure_failure_flags: Option<u32>,
        cancelled: bool,
        handle_closed: bool,
    }

    pub(crate) struct AsyncWinHttpContext {
        expected_handle: usize,
        callback_released: AtomicBool,
        state: Mutex<AsyncWinHttpState>,
        cv: Condvar,
        io_buf: Mutex<Vec<u8>>,
    }

    impl AsyncWinHttpContext {
        fn new(expected_handle: usize) -> Self {
            Self {
                expected_handle,
                callback_released: AtomicBool::new(false),
                state: Mutex::new(AsyncWinHttpState {
                    outcome: AsyncWaitOutcome::Pending,
                    last_secure_failure_flags: None,
                    cancelled: false,
                    handle_closed: false,
                }),
                cv: Condvar::new(),
                io_buf: Mutex::new(Vec::new()),
            }
        }

        fn prepare_wait(&self) {
            let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
            guard.outcome = if guard.cancelled {
                AsyncWaitOutcome::Cancelled
            } else {
                AsyncWaitOutcome::Pending
            };
        }

        pub(crate) fn mark_cancelled(&self) {
            let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
            guard.cancelled = true;
            guard.outcome = AsyncWaitOutcome::Cancelled;
            self.cv.notify_all();
        }

        fn complete(&self, outcome: AsyncWaitOutcome) {
            let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if !guard.cancelled {
                guard.outcome = outcome;
            }
            self.cv.notify_all();
        }

        fn record_secure_failure(&self, flags: Option<u32>) {
            let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
            guard.last_secure_failure_flags = flags;
        }

        fn complete_request_error(&self, msg: String) {
            let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if !guard.cancelled {
                let full = if let Some(flags) = guard.last_secure_failure_flags {
                    format!("{msg} (tls_flags=0x{flags:08X})")
                } else {
                    msg
                };
                guard.outcome = AsyncWaitOutcome::Error(full);
            }
            self.cv.notify_all();
        }

        fn complete_handle_closing(&self) {
            let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
            guard.handle_closed = true;
            if matches!(guard.outcome, AsyncWaitOutcome::Pending) {
                guard.outcome = if guard.cancelled {
                    AsyncWaitOutcome::Cancelled
                } else {
                    AsyncWaitOutcome::Error("WinHTTP request handle closed unexpectedly".into())
                };
            }
            self.cv.notify_all();
        }

        fn wait_for_outcome(&self, cancel: &CancelToken) -> AsyncWaitOutcome {
            let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
            loop {
                if guard.cancelled || cancel.is_cancelled() {
                    return AsyncWaitOutcome::Cancelled;
                }
                match &guard.outcome {
                    AsyncWaitOutcome::Pending => {
                        let (next_guard, _) = self
                            .cv
                            .wait_timeout(guard, Duration::from_millis(250))
                            .unwrap_or_else(|e| e.into_inner());
                        guard = next_guard;
                    }
                    _ => {
                        return std::mem::replace(&mut guard.outcome, AsyncWaitOutcome::Pending);
                    }
                }
            }
        }

        fn wait_for_handle_closing(&self, timeout: Duration) {
            let deadline = Instant::now() + timeout;
            let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
            while !guard.handle_closed {
                let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
                    break;
                };
                if rem.is_zero() {
                    break;
                }
                let (next_guard, wait_res) = self
                    .cv
                    .wait_timeout(guard, rem)
                    .unwrap_or_else(|e| e.into_inner());
                guard = next_guard;
                if wait_res.timed_out() {
                    break;
                }
            }
        }
    }

    unsafe extern "system" fn winhttp_async_status_callback(
        h_internet: *mut c_void,
        dw_context: usize,
        dw_internet_status: u32,
        lpv_status_information: *mut c_void,
        dw_status_information_length: u32,
    ) {
        if dw_context == 0 {
            return;
        }
        let ctx_ptr = dw_context as *const AsyncWinHttpContext;
        // SAFETY: `Arc::into_raw` keeps `AsyncWinHttpContext` alive until
        // `WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING` releases it below.
        let ctx = unsafe { &*ctx_ptr };
        if (h_internet as usize) != ctx.expected_handle {
            return;
        }

        match dw_internet_status {
            WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE => {
                ctx.complete(AsyncWaitOutcome::SendRequestComplete);
            }
            WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE => {
                ctx.complete(AsyncWaitOutcome::HeadersAvailable);
            }
            WINHTTP_CALLBACK_STATUS_DATA_AVAILABLE => {
                if !lpv_status_information.is_null()
                    && dw_status_information_length as usize >= std::mem::size_of::<u32>()
                {
                    // SAFETY: WinHTTP passes `*const u32` (`DWORD*`) for `DATA_AVAILABLE`.
                    let avail = unsafe { *(lpv_status_information as *const u32) };
                    ctx.complete(AsyncWaitOutcome::DataAvailable(avail));
                } else {
                    ctx.complete(AsyncWaitOutcome::Error(
                        "WinHTTP DATA_AVAILABLE missing byte count".to_string(),
                    ));
                }
            }
            WINHTTP_CALLBACK_STATUS_READ_COMPLETE => {
                ctx.complete(AsyncWaitOutcome::ReadComplete(dw_status_information_length));
            }
            WINHTTP_CALLBACK_STATUS_SECURE_FAILURE => {
                let flags = if !lpv_status_information.is_null()
                    && dw_status_information_length as usize >= std::mem::size_of::<u32>()
                {
                    // SAFETY: WinHTTP passes `*const u32` flags for `SECURE_FAILURE`.
                    Some(unsafe { *(lpv_status_information as *const u32) })
                } else {
                    None
                };
                ctx.record_secure_failure(flags);
            }
            WINHTTP_CALLBACK_STATUS_REQUEST_ERROR => {
                let msg = if !lpv_status_information.is_null()
                    && dw_status_information_length as usize
                        >= std::mem::size_of::<WinHttpAsyncResult>()
                {
                    // SAFETY: WinHTTP passes `*const WinHttpAsyncResult` for `REQUEST_ERROR`.
                    let res = unsafe { &*(lpv_status_information as *const WinHttpAsyncResult) };
                    let os_err = std::io::Error::from_raw_os_error(res.dw_error as i32);
                    format!(
                        "async error {} ({os_err}) at op={}",
                        res.dw_error, res.dw_result
                    )
                } else {
                    "unknown async WinHTTP request error".to_string()
                };
                ctx.complete_request_error(msg);
            }
            WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING => {
                ctx.complete_handle_closing();
                if !ctx.callback_released.swap(true, Ordering::AcqRel) {
                    // SAFETY: Releases the `Arc::into_raw` count reserved for the callback.
                    unsafe {
                        drop(Arc::from_raw(ctx_ptr));
                    }
                }
            }
            _ => {}
        }
    }

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

    struct CancellableWinHttpHandle<'a> {
        cancel: &'a CancelToken,
        raw: *mut c_void,
        ctx: Arc<AsyncWinHttpContext>,
        cb_raw: usize,
    }

    impl<'a> CancellableWinHttpHandle<'a> {
        fn register(
            cancel: &'a CancelToken,
            raw_request: *mut c_void,
            ctx: Arc<AsyncWinHttpContext>,
            cb_raw: usize,
        ) -> Result<Self, UpdaterError> {
            let registered = cancel.register_active_ctx(Arc::clone(&ctx));
            if !registered {
                ctx.mark_cancelled();
                // SAFETY: `raw_request` has callback installed; `WinHttpCloseHandle` triggers
                // `HANDLE_CLOSING` which releases `cb_raw`'s `Arc`.
                unsafe {
                    let _ = WinHttpCloseHandle(raw_request);
                }
                ctx.wait_for_handle_closing(Duration::from_millis(150));
                return Err(UpdaterError::Cancelled);
            }
            Ok(Self {
                cancel,
                raw: raw_request,
                ctx,
                cb_raw,
            })
        }

        fn raw(&self) -> *mut c_void {
            self.raw
        }

        fn ctx(&self) -> &AsyncWinHttpContext {
            &self.ctx
        }

        fn context_value(&self) -> usize {
            self.cb_raw
        }
    }

    impl Drop for CancellableWinHttpHandle<'_> {
        fn drop(&mut self) {
            self.cancel.clear_active_ctx(&self.ctx);
            if !self.raw.is_null() {
                // SAFETY: `self.raw` is closed exclusively on the owning fetch thread after all
                // WinHTTP calls have returned; `HANDLE_CLOSING` releases `cb_raw`.
                unsafe {
                    let _ = WinHttpCloseHandle(self.raw);
                }
                self.raw = ptr::null_mut();
                self.ctx.wait_for_handle_closing(Duration::from_millis(150));
            }
        }
    }

    fn to_wide_nul(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn configure_tls_and_redirects(session: *mut c_void) -> Result<(), UpdaterError> {
        let mut protocols: u32 =
            WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
        // SAFETY: `session` is a valid WinHTTP session handle and `protocols` is a 4-byte `u32`.
        let tls_ok = unsafe {
            WinHttpSetOption(
                session,
                WINHTTP_OPTION_SECURE_PROTOCOLS,
                (&protocols as *const u32).cast::<c_void>(),
                std::mem::size_of::<u32>() as u32,
            )
        };
        if tls_ok == FALSE {
            // SAFETY: Reads thread-local Win32 error immediately after `WinHttpSetOption`.
            let err_code = unsafe { GetLastError() };
            if err_code == ERROR_INVALID_PARAMETER {
                protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
                // SAFETY: Fallback to TLS 1.2 only on builds that reject `TLS1_3` flag.
                let tls12_ok = unsafe {
                    WinHttpSetOption(
                        session,
                        WINHTTP_OPTION_SECURE_PROTOCOLS,
                        (&protocols as *const u32).cast::<c_void>(),
                        std::mem::size_of::<u32>() as u32,
                    )
                };
                if tls12_ok == FALSE {
                    return Err(UpdaterError::HttpError(format!(
                        "WinHttpSetOption(SECURE_PROTOCOLS TLS1.2) failed: {}",
                        std::io::Error::last_os_error()
                    )));
                }
            } else {
                return Err(UpdaterError::HttpError(format!(
                    "WinHttpSetOption(SECURE_PROTOCOLS) failed: {}",
                    std::io::Error::from_raw_os_error(err_code as i32)
                )));
            }
        }

        let redirect_policy: u32 = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
        // SAFETY: Disables all automatic redirects so the manual hop loop enforces host/HTTPS rules.
        let redir_ok = unsafe {
            WinHttpSetOption(
                session,
                WINHTTP_OPTION_REDIRECT_POLICY,
                (&redirect_policy as *const u32).cast::<c_void>(),
                std::mem::size_of::<u32>() as u32,
            )
        };
        if redir_ok == FALSE {
            return Err(UpdaterError::HttpError(format!(
                "WinHttpSetOption(REDIRECT_POLICY_NEVER) failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        Ok(())
    }

    fn query_optional_header_string(
        request: *mut c_void,
        info_level: u32,
    ) -> Result<Option<String>, UpdaterError> {
        let mut len_bytes: u32 = 0;
        // SAFETY: First probe call determines required buffer length in bytes.
        let ok = unsafe {
            WinHttpQueryHeaders(
                request,
                info_level,
                ptr::null(),
                ptr::null_mut(),
                &mut len_bytes,
                ptr::null_mut(),
            )
        };
        if ok != FALSE {
            return Ok(Some(String::new()));
        }
        // SAFETY: Reads thread-local Win32 error immediately after `WinHttpQueryHeaders`.
        let err_code = unsafe { GetLastError() };
        if err_code == ERROR_WINHTTP_HEADER_NOT_FOUND {
            return Ok(None);
        }
        if err_code != ERROR_INSUFFICIENT_BUFFER || len_bytes == 0 {
            return Err(UpdaterError::HttpError(format!(
                "WinHttpQueryHeaders probe failed: {}",
                std::io::Error::from_raw_os_error(err_code as i32)
            )));
        }

        let u16_len = (len_bytes as usize).div_ceil(2) + 1;
        let mut buf = vec![0u16; u16_len];
        let mut actual_bytes = len_bytes;
        // SAFETY: `buf` is sized to `actual_bytes` bytes.
        let ok2 = unsafe {
            WinHttpQueryHeaders(
                request,
                info_level,
                ptr::null(),
                buf.as_mut_ptr().cast::<c_void>(),
                &mut actual_bytes,
                ptr::null_mut(),
            )
        };
        if ok2 == FALSE {
            return Err(UpdaterError::HttpError(format!(
                "WinHttpQueryHeaders read failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        let char_count = (actual_bytes as usize / 2).min(buf.len());
        let s = String::from_utf16(&buf[..char_count]).map_err(|_| {
            UpdaterError::HttpError("WinHTTP header contained invalid UTF-16".to_string())
        })?;
        Ok(Some(s.trim_end_matches('\0').to_string()))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn download_bounded(
        config: &HttpClientConfig,
        initial_url: &str,
        max_bytes: u64,
        kind: &'static str,
        expected_size_bytes: Option<u64>,
        writer: &mut dyn Write,
        cancel: &CancelToken,
        on_progress: &mut dyn FnMut(DownloadProgress),
    ) -> Result<u64, UpdaterError> {
        if cancel.is_cancelled() {
            return Err(UpdaterError::Cancelled);
        }

        let agent_w = to_wide_nul("LocalEDR-Updater/0.1");
        // SAFETY: `agent_w` is NUL-terminated UTF-16; returned handle wrapped in `OwnedWinHttpHandle`.
        let raw_session = unsafe {
            let h = WinHttpOpen(
                agent_w.as_ptr(),
                WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                ptr::null(),
                ptr::null(),
                WINHTTP_FLAG_ASYNC,
            );
            if h.is_null() {
                WinHttpOpen(
                    agent_w.as_ptr(),
                    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                    ptr::null(),
                    ptr::null(),
                    WINHTTP_FLAG_ASYNC,
                )
            } else {
                h
            }
        };
        if raw_session.is_null() {
            return Err(UpdaterError::HttpError(format!(
                "WinHttpOpen failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        let session = OwnedWinHttpHandle(raw_session);

        // SAFETY: `session.0` is an open WinHTTP session handle.
        let timeout_ok = unsafe {
            WinHttpSetTimeouts(
                session.0,
                config.connect_send_timeout_ms,
                config.connect_send_timeout_ms,
                config.connect_send_timeout_ms,
                config.receive_timeout_ms,
            )
        };
        if timeout_ok == FALSE {
            return Err(UpdaterError::HttpError(format!(
                "WinHttpSetTimeouts failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        configure_tls_and_redirects(session.0)?;

        let verb_w = to_wide_nul("GET");
        let mut current_url = initial_url.to_string();

        for hop in 0..=config.max_redirect_hops {
            if cancel.is_cancelled() {
                return Err(UpdaterError::Cancelled);
            }

            let parsed = parse_http_url(&current_url)?;
            let host_w = to_wide_nul(&parsed.host);
            let path_w = to_wide_nul(&parsed.path_and_query);

            // SAFETY: `session.0` is valid and `host_w` is NUL-terminated UTF-16.
            let raw_connect = unsafe { WinHttpConnect(session.0, host_w.as_ptr(), parsed.port, 0) };
            if raw_connect.is_null() {
                let err = std::io::Error::last_os_error();
                if cancel.is_cancelled() {
                    return Err(UpdaterError::Cancelled);
                }
                return Err(UpdaterError::HttpError(format!(
                    "WinHttpConnect({}:{}) failed: {err}",
                    parsed.host, parsed.port
                )));
            }
            let connect = OwnedWinHttpHandle(raw_connect);

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
                let err = std::io::Error::last_os_error();
                if cancel.is_cancelled() {
                    return Err(UpdaterError::Cancelled);
                }
                return Err(UpdaterError::HttpError(format!(
                    "WinHttpOpenRequest({}) failed: {err}",
                    parsed.path_and_query
                )));
            }

            let redirect_policy: u32 = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
            // SAFETY: Enforce redirect policy directly on request handle as defense-in-depth.
            let req_redir_ok = unsafe {
                WinHttpSetOption(
                    raw_request,
                    WINHTTP_OPTION_REDIRECT_POLICY,
                    (&redirect_policy as *const u32).cast::<c_void>(),
                    std::mem::size_of::<u32>() as u32,
                )
            };
            if req_redir_ok == FALSE {
                let err = std::io::Error::last_os_error();
                unsafe {
                    let _ = WinHttpCloseHandle(raw_request);
                }
                return Err(UpdaterError::HttpError(format!(
                    "WinHttpSetOption(request REDIRECT_POLICY_NEVER) failed: {err}"
                )));
            }

            let ctx = Arc::new(AsyncWinHttpContext::new(raw_request as usize));
            let cb_ptr = Arc::into_raw(Arc::clone(&ctx));
            let cb_raw = cb_ptr as usize;

            // SAFETY: Associates `cb_raw` before callback registration.
            let set_ctx_ok = unsafe {
                WinHttpSetOption(
                    raw_request,
                    WINHTTP_OPTION_CONTEXT_VALUE,
                    (&cb_raw as *const usize).cast::<c_void>(),
                    std::mem::size_of::<usize>() as u32,
                )
            };
            if set_ctx_ok == FALSE {
                let err = std::io::Error::last_os_error();
                unsafe {
                    drop(Arc::from_raw(cb_ptr));
                    let _ = WinHttpCloseHandle(raw_request);
                }
                return Err(UpdaterError::HttpError(format!(
                    "WinHttpSetOption(CONTEXT_VALUE) failed: {err}"
                )));
            }

            // SAFETY: Callback remains valid until `HANDLE_CLOSING` releases `cb_ptr`.
            let prev_cb = unsafe {
                WinHttpSetStatusCallback(
                    raw_request,
                    Some(winhttp_async_status_callback),
                    WINHTTP_CALLBACK_FLAG_ALL_NOTIFICATIONS,
                    0,
                )
            };
            if (prev_cb as usize) == usize::MAX {
                let err = std::io::Error::last_os_error();
                unsafe {
                    drop(Arc::from_raw(cb_ptr));
                    let _ = WinHttpCloseHandle(raw_request);
                }
                return Err(UpdaterError::HttpError(format!(
                    "WinHttpSetStatusCallback failed: {err}"
                )));
            }

            let request = CancellableWinHttpHandle::register(cancel, raw_request, ctx, cb_raw)?;

            request.ctx().prepare_wait();
            // SAFETY: `request.raw()` is open with registered callback and `cb_raw` context.
            let send_ok = unsafe {
                WinHttpSendRequest(
                    request.raw(),
                    ptr::null(),
                    0,
                    ptr::null_mut(),
                    0,
                    0,
                    request.context_value(),
                )
            };
            if send_ok == FALSE {
                let err = std::io::Error::last_os_error();
                if cancel.is_cancelled() {
                    return Err(UpdaterError::Cancelled);
                }
                return Err(UpdaterError::HttpError(format!(
                    "WinHttpSendRequest failed: {err}"
                )));
            }
            match request.ctx().wait_for_outcome(cancel) {
                AsyncWaitOutcome::SendRequestComplete => {}
                AsyncWaitOutcome::Cancelled => return Err(UpdaterError::Cancelled),
                AsyncWaitOutcome::Error(msg) => {
                    return Err(UpdaterError::HttpError(format!(
                        "WinHttpSendRequest failed: {msg}"
                    )))
                }
                other => {
                    return Err(UpdaterError::HttpError(format!(
                        "WinHttpSendRequest unexpected async outcome: {other:?}"
                    )))
                }
            }

            request.ctx().prepare_wait();
            // SAFETY: `WinHttpSendRequest` completed for `request.raw()`.
            let recv_ok = unsafe { WinHttpReceiveResponse(request.raw(), ptr::null_mut()) };
            if recv_ok == FALSE {
                let err = std::io::Error::last_os_error();
                if cancel.is_cancelled() {
                    return Err(UpdaterError::Cancelled);
                }
                return Err(UpdaterError::HttpError(format!(
                    "WinHttpReceiveResponse failed: {err}"
                )));
            }
            match request.ctx().wait_for_outcome(cancel) {
                AsyncWaitOutcome::HeadersAvailable => {}
                AsyncWaitOutcome::Cancelled => return Err(UpdaterError::Cancelled),
                AsyncWaitOutcome::Error(msg) => {
                    return Err(UpdaterError::HttpError(format!(
                        "WinHttpReceiveResponse failed: {msg}"
                    )))
                }
                other => {
                    return Err(UpdaterError::HttpError(format!(
                        "WinHttpReceiveResponse unexpected async outcome: {other:?}"
                    )))
                }
            }

            let mut status_code: u32 = 0;
            let mut status_len = std::mem::size_of::<u32>() as u32;
            // SAFETY: Queries numeric HTTP status code into `status_code`.
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
            if hdr_ok == FALSE {
                let err = std::io::Error::last_os_error();
                if cancel.is_cancelled() {
                    return Err(UpdaterError::Cancelled);
                }
                return Err(UpdaterError::HttpError(format!(
                    "WinHttpQueryHeaders(STATUS_CODE) failed: {err}"
                )));
            }

            match status_code {
                301 | 302 | 303 | 307 | 308 => {
                    if hop >= config.max_redirect_hops {
                        return Err(UpdaterError::HttpError(format!(
                            "exceeded max redirect hops ({})",
                            config.max_redirect_hops
                        )));
                    }
                    let loc = query_optional_header_string(request.raw(), WINHTTP_QUERY_LOCATION)?
                        .ok_or_else(|| {
                            UpdaterError::HttpError(format!(
                                "HTTP {status_code} redirect missing Location header"
                            ))
                        })?;
                    let next_url = resolve_redirect_location(&parsed, &loc)?;
                    validate_download_url(&next_url, config.allow_loopback_http_for_tests)?;
                    tracing::debug!(
                        hop = hop + 1,
                        status = status_code,
                        next_url = %next_url,
                        "following validated manual update redirect"
                    );
                    current_url = next_url;
                    continue;
                }
                200 => {
                    let content_length = query_optional_header_string(
                        request.raw(),
                        WINHTTP_QUERY_CONTENT_LENGTH,
                    )?
                    .map(|s| {
                        s.trim().parse::<u64>().map_err(|_| {
                            UpdaterError::HttpError(format!(
                                "invalid Content-Length header {s:?}"
                            ))
                        })
                    })
                    .transpose()?;

                    if let Some(cl) = content_length {
                        if cl > max_bytes {
                            return Err(UpdaterError::ResponseTooLarge {
                                kind,
                                limit_bytes: max_bytes.min(usize::MAX as u64) as usize,
                                actual_bytes: cl.min(usize::MAX as u64) as usize,
                            });
                        }
                        if let Some(exp) = expected_size_bytes {
                            if cl != exp {
                                return Err(UpdaterError::SizeMismatch {
                                    expected: exp,
                                    actual: cl,
                                });
                            }
                        }
                    }

                    let mut total_read: u64 = 0;
                    loop {
                        if cancel.is_cancelled() {
                            return Err(UpdaterError::Cancelled);
                        }

                        request.ctx().prepare_wait();
                        // SAFETY: Async `WinHttpQueryDataAvailable` requires NULL out-pointer.
                        let avail_ok =
                            unsafe { WinHttpQueryDataAvailable(request.raw(), ptr::null_mut()) };
                        if avail_ok == FALSE {
                            let err = std::io::Error::last_os_error();
                            if cancel.is_cancelled() {
                                return Err(UpdaterError::Cancelled);
                            }
                            return Err(UpdaterError::HttpError(format!(
                                "WinHttpQueryDataAvailable failed: {err}"
                            )));
                        }
                        let avail = match request.ctx().wait_for_outcome(cancel) {
                            AsyncWaitOutcome::DataAvailable(avail) => avail,
                            AsyncWaitOutcome::Cancelled => return Err(UpdaterError::Cancelled),
                            AsyncWaitOutcome::Error(msg) => {
                                return Err(UpdaterError::HttpError(format!(
                                    "WinHttpQueryDataAvailable failed: {msg}"
                                )))
                            }
                            other => {
                                return Err(UpdaterError::HttpError(format!(
                                    "WinHttpQueryDataAvailable unexpected async outcome: {other:?}"
                                )))
                            }
                        };
                        if avail == 0 {
                            break;
                        }
                        if cancel.is_cancelled() {
                            return Err(UpdaterError::Cancelled);
                        }

                        let remaining_plus_sentinel = max_bytes
                            .saturating_sub(total_read)
                            .saturating_add(1)
                            .min(READ_CHUNK_BYTES as u64) as usize;
                        let to_read = (avail as usize).min(remaining_plus_sentinel).max(1);

                        let buf_ptr = {
                            let mut io = request
                                .ctx()
                                .io_buf
                                .lock()
                                .unwrap_or_else(|e| e.into_inner());
                            if io.len() < to_read {
                                io.resize(to_read, 0);
                            }
                            io.as_mut_ptr()
                        };

                        request.ctx().prepare_wait();
                        // SAFETY: `buf_ptr` points to heap-allocated `io_buf` owned by `Arc<AsyncWinHttpContext>`.
                        let read_ok = unsafe {
                            WinHttpReadData(
                                request.raw(),
                                buf_ptr.cast::<c_void>(),
                                to_read as u32,
                                ptr::null_mut(),
                            )
                        };
                        if read_ok == FALSE {
                            let err = std::io::Error::last_os_error();
                            if cancel.is_cancelled() {
                                return Err(UpdaterError::Cancelled);
                            }
                            return Err(UpdaterError::HttpError(format!(
                                "WinHttpReadData failed: {err}"
                            )));
                        }
                        let read_len = match request.ctx().wait_for_outcome(cancel) {
                            AsyncWaitOutcome::ReadComplete(read_len) => read_len,
                            AsyncWaitOutcome::Cancelled => return Err(UpdaterError::Cancelled),
                            AsyncWaitOutcome::Error(msg) => {
                                return Err(UpdaterError::HttpError(format!(
                                    "WinHttpReadData failed: {msg}"
                                )))
                            }
                            other => {
                                return Err(UpdaterError::HttpError(format!(
                                    "WinHttpReadData unexpected async outcome: {other:?}"
                                )))
                            }
                        };
                        if read_len == 0 {
                            break;
                        }

                        let n = (read_len as usize).min(to_read);
                        let new_total = total_read.checked_add(n as u64).ok_or_else(|| {
                            UpdaterError::ResponseTooLarge {
                                kind,
                                limit_bytes: max_bytes.min(usize::MAX as u64) as usize,
                                actual_bytes: usize::MAX,
                            }
                        })?;
                        if new_total > max_bytes {
                            return Err(UpdaterError::ResponseTooLarge {
                                kind,
                                limit_bytes: max_bytes.min(usize::MAX as u64) as usize,
                                actual_bytes: new_total.min(usize::MAX as u64) as usize,
                            });
                        }

                        {
                            let io = request
                                .ctx()
                                .io_buf
                                .lock()
                                .unwrap_or_else(|e| e.into_inner());
                            writer.write_all(&io[..n])?;
                        }
                        total_read = new_total;
                        on_progress(DownloadProgress {
                            bytes_downloaded: total_read,
                            total_bytes: content_length,
                        });
                    }

                    if let Some(cl) = content_length {
                        if total_read != cl {
                            return Err(UpdaterError::HttpError(format!(
                                "truncated {kind} response body: expected {cl} bytes, got {total_read}"
                            )));
                        }
                    }

                    tracing::debug!(
                        kind,
                        bytes = total_read,
                        url = %current_url,
                        "completed bounded WinHTTP download"
                    );
                    return Ok(total_read);
                }
                other => {
                    return Err(UpdaterError::HttpError(format!(
                        "unexpected HTTP status {other} from {current_url}"
                    )));
                }
            }
        }

        Err(UpdaterError::HttpError(format!(
            "exceeded max redirect hops ({})",
            config.max_redirect_hops
        )))
    }
}

#[cfg(not(windows))]
mod windows_impl {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    pub(super) fn download_bounded(
        _config: &HttpClientConfig,
        _initial_url: &str,
        _max_bytes: u64,
        _kind: &'static str,
        _expected_size_bytes: Option<u64>,
        _writer: &mut dyn Write,
        cancel: &CancelToken,
        _on_progress: &mut dyn FnMut(DownloadProgress),
    ) -> Result<u64, UpdaterError> {
        if cancel.is_cancelled() {
            return Err(UpdaterError::Cancelled);
        }
        Err(UpdaterError::HttpError(
            "WinHTTP updater transport is only supported on Windows".to_string(),
        ))
    }
}
