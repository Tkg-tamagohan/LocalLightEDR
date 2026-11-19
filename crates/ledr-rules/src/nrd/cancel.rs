//! Cooperative cancellation token and blocking-read guard for NRD operations.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

#[cfg(windows)]
use super::winhttp_ctx::AsyncWinHttpContext;

#[derive(Default)]
pub(super) struct NrdCancelState {
    pub(super) cancelled: AtomicBool,
    blocking_read_active: AtomicBool,
    blocking_read_entries: AtomicU64,
    #[cfg(windows)]
    pub(super) active_ctx: std::sync::Mutex<Option<Arc<AsyncWinHttpContext>>>,
}

/// RAII guard marking an in-flight synchronous `Read::read()` call on [`NrdCancelToken`].
pub(crate) struct BlockingReadGuard<'a> {
    token: &'a NrdCancelToken,
}

impl Drop for BlockingReadGuard<'_> {
    fn drop(&mut self) {
        self.token
            .state
            .blocking_read_active
            .store(false, Ordering::Release);
    }
}

/// Cooperative cancellation token for [`fetch_nrd_feed_url_cancellable`](super::fetch_nrd_feed_url_cancellable) and
/// [`refresh_nrd_cache_cancellable`](super::refresh_nrd_cache_cancellable).
#[derive(Clone, Default)]
pub struct NrdCancelToken {
    pub(super) state: Arc<NrdCancelState>,
}

impl std::fmt::Debug for NrdCancelToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NrdCancelToken")
            .field("cancelled", &self.is_cancelled())
            .field("blocking_read_active", &self.is_blocking_read_active())
            .field("blocking_read_entries", &self.blocking_read_entries())
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

    /// Returns `true` while a cancellable bounded reader is currently inside a synchronous
    /// `Read::read()` call associated with this token.
    pub fn is_blocking_read_active(&self) -> bool {
        self.state.blocking_read_active.load(Ordering::Acquire)
    }

    /// Returns the total number of synchronous `Read::read()` calls entered with this token.
    pub fn blocking_read_entries(&self) -> u64 {
        self.state.blocking_read_entries.load(Ordering::Acquire)
    }

    /// Marks entry into a synchronous `Read::read()` call and returns an RAII guard that resets
    /// `blocking_read_active` to `false` on drop.
    ///
    /// Sets `blocking_read_active` to `true` (`Release`) before incrementing
    /// `blocking_read_entries` (`AcqRel`) so any observer that sees `blocking_read_entries() >= N`
    /// with `Acquire` immediately sees `is_blocking_read_active() == true` while the reader is
    /// still inside `read()`.
    pub(crate) fn enter_blocking_read(&self) -> BlockingReadGuard<'_> {
        self.state
            .blocking_read_active
            .store(true, Ordering::Release);
        self.state
            .blocking_read_entries
            .fetch_add(1, Ordering::AcqRel);
        BlockingReadGuard { token: self }
    }

    /// Cancels any current or future NRD fetch associated with this token.
    ///
    /// On Windows, wakes any waiting async WinHTTP operation immediately via `AsyncWinHttpContext`
    /// so the owning fetch thread unwinds and closes `HINTERNET` handles on its own thread with
    /// zero cross-thread `WinHttpCloseHandle` vs `WinHttpSendRequest`/`WinHttpReadData` races.
    pub fn cancel(&self) {
        self.state.cancelled.store(true, Ordering::SeqCst);
        #[cfg(windows)]
        {
            let active = {
                let mut guard = self
                    .state
                    .active_ctx
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                guard.take()
            };
            if let Some(ctx) = active {
                ctx.mark_cancelled();
            }
        }
    }
}
