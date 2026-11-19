//! Async WinHTTP callback synchronization state and buffer context.

use std::sync::atomic::AtomicBool;

#[derive(Debug)]
pub(super) enum AsyncWaitOutcome {
    Pending,
    SendRequestComplete,
    HeadersAvailable,
    DataAvailable(u32),
    ReadComplete(u32),
    Error(String),
    Cancelled,
}

#[cfg(windows)]
pub(super) struct AsyncWinHttpState {
    pub(super) outcome: AsyncWaitOutcome,
    pub(super) last_secure_failure_flags: Option<u32>,
    pub(super) cancelled: bool,
    pub(super) handle_closed: bool,
}

#[cfg(windows)]
pub(super) struct AsyncWinHttpContext {
    pub(super) expected_handle: usize,
    pub(super) callback_released: AtomicBool,
    pub(super) state: std::sync::Mutex<AsyncWinHttpState>,
    pub(super) cv: std::sync::Condvar,
    // Heap-backed I/O buffer kept inside this `Arc`-owned context so that even if
    // cancellation causes `fetch_http_winhttp_cancellable` to unwind before
    // `WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING`, WinHTTP never sees a dangling stack buffer.
    pub(super) io_buf: std::sync::Mutex<Vec<u8>>,
}

#[cfg(windows)]
impl AsyncWinHttpContext {
    pub(super) fn new(expected_handle: usize) -> Self {
        Self {
            expected_handle,
            callback_released: AtomicBool::new(false),
            state: std::sync::Mutex::new(AsyncWinHttpState {
                outcome: AsyncWaitOutcome::Pending,
                last_secure_failure_flags: None,
                cancelled: false,
                handle_closed: false,
            }),
            cv: std::sync::Condvar::new(),
            io_buf: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub(super) fn prepare_wait(&self) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        guard.outcome = if guard.cancelled {
            AsyncWaitOutcome::Cancelled
        } else {
            AsyncWaitOutcome::Pending
        };
    }

    pub(super) fn mark_cancelled(&self) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        guard.cancelled = true;
        guard.outcome = AsyncWaitOutcome::Cancelled;
        self.cv.notify_all();
    }

    pub(super) fn complete(&self, outcome: AsyncWaitOutcome) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if !guard.cancelled {
            guard.outcome = outcome;
        }
        self.cv.notify_all();
    }

    pub(super) fn record_secure_failure(&self, flags: Option<u32>) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        guard.last_secure_failure_flags = flags;
    }

    pub(super) fn complete_request_error(&self, msg: String) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if !guard.cancelled {
            let full_msg = if let Some(flags) = guard.last_secure_failure_flags {
                format!("{msg} (tls_flags=0x{flags:08X})")
            } else {
                msg
            };
            guard.outcome = AsyncWaitOutcome::Error(full_msg);
        }
        self.cv.notify_all();
    }

    pub(super) fn complete_handle_closing(&self) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        guard.handle_closed = true;
        if matches!(guard.outcome, AsyncWaitOutcome::Pending) {
            guard.outcome = if guard.cancelled {
                AsyncWaitOutcome::Cancelled
            } else {
                AsyncWaitOutcome::Error("WinHTTP request handle closed unexpectedly".to_string())
            };
        }
        self.cv.notify_all();
    }

    pub(super) fn wait_for_handle_closing(&self, timeout: std::time::Duration) {
        let deadline = std::time::Instant::now() + timeout;
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        while !guard.handle_closed {
            let Some(rem) = deadline.checked_duration_since(std::time::Instant::now()) else {
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
