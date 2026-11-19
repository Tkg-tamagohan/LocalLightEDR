//! Async WinHTTP NRD feed downloader and non-Windows stub.

#[cfg(windows)]
use std::sync::atomic::Ordering;
#[cfg(windows)]
use std::sync::Arc;

use super::cancel::NrdCancelToken;
#[cfg(windows)]
use super::reader::read_bounded_chunks_cancellable;
use super::url::ParsedHttpUrl;
#[cfg(windows)]
use super::winhttp_ctx::{AsyncWaitOutcome, AsyncWinHttpContext};
#[cfg(windows)]
use super::winhttp_ffi;

#[cfg(windows)]
impl AsyncWinHttpContext {
    pub(super) fn wait_for_outcome(&self, cancel: &NrdCancelToken) -> AsyncWaitOutcome {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if guard.cancelled || cancel.is_cancelled() {
                return AsyncWaitOutcome::Cancelled;
            }
            match &guard.outcome {
                AsyncWaitOutcome::Pending => {
                    let (next_guard, _) = self
                        .cv
                        .wait_timeout(guard, std::time::Duration::from_millis(250))
                        .unwrap_or_else(|e| e.into_inner());
                    guard = next_guard;
                }
                _ => {
                    return std::mem::replace(&mut guard.outcome, AsyncWaitOutcome::Pending);
                }
            }
        }
    }
}

#[cfg(windows)]
unsafe extern "system" fn winhttp_async_status_callback(
    h_internet: *mut std::ffi::c_void,
    dw_context: usize,
    dw_internet_status: u32,
    lpv_status_information: *mut std::ffi::c_void,
    dw_status_information_length: u32,
) {
    use winhttp_ffi::*;

    if dw_context == 0 {
        return;
    }
    let ctx_ptr = dw_context as *const AsyncWinHttpContext;
    // SAFETY: `cb_ptr = Arc::into_raw(...)` keeps `AsyncWinHttpContext` alive until
    // `WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING` releases that ref below, which WinHTTP guarantees
    // is the final callback ever delivered for this handle.
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
                // SAFETY: WinHTTP passes `*const u32` (`DWORD*`) flags for `SECURE_FAILURE`.
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
                // SAFETY: Releases the `Arc::into_raw` count reserved for the WinHTTP callback.
                // No WinHTTP callback can fire for this handle after `HANDLE_CLOSING`.
                unsafe {
                    drop(Arc::from_raw(ctx_ptr));
                }
            }
        }
        _ => {}
    }
}

#[cfg(windows)]
pub(super) fn fetch_http_winhttp_cancellable(
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

    // RAII guard for the async request handle: registers `AsyncWinHttpContext` for cross-thread
    // wakeups (`cancel()`) while ensuring `WinHttpCloseHandle(self.raw)` is invoked EXCLUSIVELY
    // on this owning fetch thread after all `WinHttp*` calls have returned.
    struct CancellableWinHttpHandle<'a> {
        cancel: &'a NrdCancelToken,
        raw: *mut c_void,
        ctx: Arc<AsyncWinHttpContext>,
        cb_raw: usize,
    }

    impl<'a> CancellableWinHttpHandle<'a> {
        fn register(
            cancel: &'a NrdCancelToken,
            raw_request: *mut c_void,
            ctx: Arc<AsyncWinHttpContext>,
            cb_raw: usize,
        ) -> Result<Self, String> {
            let mut guard = cancel
                .state
                .active_ctx
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if cancel.state.cancelled.load(Ordering::SeqCst) {
                drop(guard);
                ctx.mark_cancelled();
                // SAFETY: `raw_request` has callback installed; `WinHttpCloseHandle` triggers
                // `WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING` which releases `cb_raw`'s `Arc`.
                unsafe {
                    let _ = WinHttpCloseHandle(raw_request);
                }
                ctx.wait_for_handle_closing(std::time::Duration::from_millis(150));
                return Err("NRD feed download cancelled".to_string());
            }
            *guard = Some(Arc::clone(&ctx));
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
            {
                let mut guard = self
                    .cancel
                    .state
                    .active_ctx
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if guard.as_ref().is_some_and(|c| Arc::ptr_eq(c, &self.ctx)) {
                    *guard = None;
                }
            }
            if !self.raw.is_null() {
                // SAFETY: `self.raw` is closed exclusively on the fetch thread after all
                // WinHTTP calls on `self.raw` have finished; `HANDLE_CLOSING` releases `cb_raw`.
                unsafe {
                    let _ = WinHttpCloseHandle(self.raw);
                }
                self.raw = ptr::null_mut();
                self.ctx
                    .wait_for_handle_closing(std::time::Duration::from_millis(150));
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

    // Open session in true async mode (`WINHTTP_FLAG_ASYNC`) so cross-thread
    // `WinHttpCloseHandle` from `NrdCancelToken::cancel()` obeys WinHTTP's handle contract.
    // SAFETY: All pointers are NUL-terminated UTF-16 or NULL; returned handles use RAII guards.
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
        let err = std::io::Error::last_os_error();
        if cancel.is_cancelled() {
            return Err("NRD feed download cancelled".to_string());
        }
        return Err(format!(
            "WinHttpConnect(`{}:{}`) failed: {err}",
            parsed.host, parsed.port
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
        let err = std::io::Error::last_os_error();
        if cancel.is_cancelled() {
            return Err("NRD feed download cancelled".to_string());
        }
        return Err(format!(
            "WinHttpOpenRequest(`{}`) failed: {err}",
            parsed.path_and_query
        ));
    }

    if cancel.is_cancelled() {
        // SAFETY: `raw_request` was opened above and no callback is installed yet.
        unsafe {
            let _ = WinHttpCloseHandle(raw_request);
        }
        return Err("NRD feed download cancelled".to_string());
    }

    let ctx = Arc::new(AsyncWinHttpContext::new(raw_request as usize));
    let cb_ptr = Arc::into_raw(Arc::clone(&ctx));
    let cb_raw = cb_ptr as usize;

    // SAFETY: Sets `cb_raw` (`*const AsyncWinHttpContext`) as request context before callback
    // registration so `HANDLE_CLOSING` always receives a valid context pointer.
    let set_ctx_ok = unsafe {
        WinHttpSetOption(
            raw_request,
            WINHTTP_OPTION_CONTEXT_VALUE,
            (&cb_raw as *const usize).cast::<c_void>(),
            std::mem::size_of::<usize>() as u32,
        )
    };
    if set_ctx_ok == 0 {
        let err = std::io::Error::last_os_error();
        // SAFETY: Callback is not installed yet; reclaim `cb_ptr` and close `raw_request`.
        unsafe {
            drop(Arc::from_raw(cb_ptr));
            let _ = WinHttpCloseHandle(raw_request);
        }
        return Err(format!("WinHttpSetOption(CONTEXT_VALUE) failed: {err}"));
    }

    // SAFETY: `raw_request` is valid and `cb_ptr` stays alive until `HANDLE_CLOSING`.
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
        // SAFETY: Callback installation failed (`WINHTTP_INVALID_STATUS_CALLBACK`); reclaim `cb_ptr`.
        unsafe {
            drop(Arc::from_raw(cb_ptr));
            let _ = WinHttpCloseHandle(raw_request);
        }
        return Err(format!("WinHttpSetStatusCallback failed: {err}"));
    }

    let request = CancellableWinHttpHandle::register(cancel, raw_request, ctx, cb_raw)?;

    if cancel.is_cancelled() {
        return Err("NRD feed download cancelled".to_string());
    }

    request.ctx().prepare_wait();
    // SAFETY: `request.raw()` is a valid async WinHTTP request handle with `cb_raw` context.
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
    if send_ok == 0 {
        let err = std::io::Error::last_os_error();
        if cancel.is_cancelled() {
            return Err("NRD feed download cancelled".to_string());
        }
        return Err(format!("WinHttpSendRequest failed: {err}"));
    }
    match request.ctx().wait_for_outcome(cancel) {
        AsyncWaitOutcome::SendRequestComplete => {}
        AsyncWaitOutcome::Cancelled => return Err("NRD feed download cancelled".to_string()),
        AsyncWaitOutcome::Error(msg) => return Err(format!("WinHttpSendRequest failed: {msg}")),
        other => {
            return Err(format!(
                "WinHttpSendRequest unexpected async outcome: {other:?}"
            ))
        }
    }

    if cancel.is_cancelled() {
        return Err("NRD feed download cancelled".to_string());
    }

    request.ctx().prepare_wait();
    // SAFETY: `request.raw()` completed `WinHttpSendRequest`.
    let recv_ok = unsafe { WinHttpReceiveResponse(request.raw(), ptr::null_mut()) };
    if recv_ok == 0 {
        let err = std::io::Error::last_os_error();
        if cancel.is_cancelled() {
            return Err("NRD feed download cancelled".to_string());
        }
        return Err(format!("WinHttpReceiveResponse failed: {err}"));
    }
    match request.ctx().wait_for_outcome(cancel) {
        AsyncWaitOutcome::HeadersAvailable => {}
        AsyncWaitOutcome::Cancelled => return Err("NRD feed download cancelled".to_string()),
        AsyncWaitOutcome::Error(msg) => {
            return Err(format!("WinHttpReceiveResponse failed: {msg}"))
        }
        other => {
            return Err(format!(
                "WinHttpReceiveResponse unexpected async outcome: {other:?}"
            ))
        }
    }

    if cancel.is_cancelled() {
        return Err("NRD feed download cancelled".to_string());
    }

    let mut status_code: u32 = 0;
    let mut status_len = std::mem::size_of::<u32>() as u32;
    // SAFETY: Queries HTTP status code into `status_code` (`DWORD`) after `HEADERS_AVAILABLE`.
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
        let err = std::io::Error::last_os_error();
        if cancel.is_cancelled() {
            return Err("NRD feed download cancelled".to_string());
        }
        return Err(format!("WinHttpQueryHeaders(STATUS_CODE) failed: {err}"));
    }
    if !(200..300).contains(&status_code) {
        return Err(format!("HTTP status {status_code}"));
    }

    read_bounded_chunks_cancellable(max_bytes, cancel, |want| {
        if cancel.is_cancelled() {
            return Err("NRD feed download cancelled".to_string());
        }

        request.ctx().prepare_wait();
        // SAFETY: In `WINHTTP_FLAG_ASYNC` mode, `WinHttpQueryDataAvailable` requires NULL for
        // `lpdw_number_of_bytes_available` and reports byte count via `DATA_AVAILABLE` callback.
        let avail_ok = unsafe { WinHttpQueryDataAvailable(request.raw(), ptr::null_mut()) };
        if avail_ok == 0 {
            let err = std::io::Error::last_os_error();
            if cancel.is_cancelled() {
                return Err("NRD feed download cancelled".to_string());
            }
            return Err(format!("WinHttpQueryDataAvailable failed: {err}"));
        }
        let avail = match request.ctx().wait_for_outcome(cancel) {
            AsyncWaitOutcome::DataAvailable(avail) => avail,
            AsyncWaitOutcome::Cancelled => return Err("NRD feed download cancelled".to_string()),
            AsyncWaitOutcome::Error(msg) => {
                return Err(format!("WinHttpQueryDataAvailable failed: {msg}"))
            }
            other => {
                return Err(format!(
                    "WinHttpQueryDataAvailable unexpected async outcome: {other:?}"
                ))
            }
        };
        if avail == 0 {
            return Ok(None);
        }
        if cancel.is_cancelled() {
            return Err("NRD feed download cancelled".to_string());
        }

        let to_read = (avail as usize).min(want).max(1);
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
        // SAFETY: `buf_ptr` points to heap memory inside `Arc<AsyncWinHttpContext>` of at least
        // `to_read` bytes, untouched until `READ_COMPLETE` or `HANDLE_CLOSING`. Async mode requires
        // NULL for `lpdw_number_of_bytes_read`.
        let read_ok = unsafe {
            WinHttpReadData(
                request.raw(),
                buf_ptr.cast::<c_void>(),
                to_read as u32,
                ptr::null_mut(),
            )
        };
        if read_ok == 0 {
            let err = std::io::Error::last_os_error();
            if cancel.is_cancelled() {
                return Err("NRD feed download cancelled".to_string());
            }
            return Err(format!("WinHttpReadData failed: {err}"));
        }
        let read_len = match request.ctx().wait_for_outcome(cancel) {
            AsyncWaitOutcome::ReadComplete(read_len) => read_len,
            AsyncWaitOutcome::Cancelled => return Err("NRD feed download cancelled".to_string()),
            AsyncWaitOutcome::Error(msg) => {
                return Err(format!("WinHttpReadData failed: {msg}"))
            }
            other => {
                return Err(format!(
                    "WinHttpReadData unexpected async outcome: {other:?}"
                ))
            }
        };
        if read_len == 0 {
            return Ok(None);
        }
        let n = (read_len as usize).min(to_read);
        let io = request
            .ctx()
            .io_buf
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        Ok(Some(io[..n].to_vec()))
    })
}

#[cfg(not(windows))]
pub(super) fn fetch_http_winhttp_cancellable(
    _parsed: &ParsedHttpUrl,
    _max_bytes: usize,
    cancel: &NrdCancelToken,
) -> Result<(Vec<u8>, bool), String> {
    if cancel.is_cancelled() {
        return Err("NRD feed download cancelled".to_string());
    }
    Err("WinHTTP NRD feed fetch is only supported on Windows".to_string())
}
