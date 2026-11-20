use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};

use ledr_rules::{
    assess_domain_risk, refresh_nrd_cache_cancellable, DomainRiskAssessment, NrdCache,
    NrdCancelToken, NrdRefreshStats, NRD_MAX_ENTRIES, NRD_MAX_RESPONSE_BYTES,
};

use super::{current_unix_ms, DaemonEngine};

pub(super) struct NrdThreadHandle {
    pub(super) join_handle: std::thread::JoinHandle<()>,
    pub(super) done_rx: tokio::sync::oneshot::Receiver<()>,
}

impl DaemonEngine {
    /// Returns `true` while a background daily NRD refresh OS thread is executing.
    pub fn is_nrd_refresh_in_flight(&self) -> bool {
        self.nrd_in_flight.load(Ordering::Acquire)
    }

    /// Returns a clone of the cooperative [`NrdCancelToken`] used by background NRD refreshes.
    pub fn nrd_cancel_token(&self) -> NrdCancelToken {
        self.nrd_cancel.clone()
    }

    /// Evaluates domain risk (NRD cache membership + Punycode/brand homograph detection, `L-14`)
    /// using the live in-memory [`NrdCache`] without cloning the domain set.
    pub fn assess_domain(&self, domain: &str) -> DomainRiskAssessment {
        let guard = self.nrd_cache.read().unwrap_or_else(|e| e.into_inner());
        assess_domain_risk(domain, Some(guard.domains()))
    }

    /// Returns the number of entries currently loaded in the live NRD cache.
    pub fn nrd_entry_count(&self) -> usize {
        self.nrd_cache
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// Replaces the in-memory [`NrdCache`] (useful for tests or explicit cache injection).
    pub fn set_nrd_cache(&self, cache: NrdCache) {
        let mut guard = self.nrd_cache.write().unwrap_or_else(|e| e.into_inner());
        *guard = cache;
    }

    /// Synchronously refreshes the NRD cache from `config.nrd_feed_urls`, persisting to
    /// `config.nrd_cache_path` when configured. Preserves the prior cache if all feeds fail.
    pub fn refresh_nrd_cache_once(&self) -> Result<NrdRefreshStats, String> {
        execute_nrd_refresh(
            &self.config.nrd_feed_urls,
            self.config.nrd_cache_path.as_deref(),
            &self.nrd_cache,
            &self.nrd_cancel,
        )
    }
}

pub(super) fn execute_nrd_refresh(
    feed_urls: &[String],
    cache_path: Option<&Path>,
    nrd_cache: &Arc<RwLock<NrdCache>>,
    cancel: &NrdCancelToken,
) -> Result<NrdRefreshStats, String> {
    let now_ms = current_unix_ms();
    let (fresh, stats) = refresh_nrd_cache_cancellable(
        feed_urls,
        NRD_MAX_ENTRIES,
        NRD_MAX_RESPONSE_BYTES,
        now_ms,
        cancel,
    )?;
    if cancel.is_cancelled() {
        return Err("NRD cache refresh cancelled".to_string());
    }
    if let Some(path) = cache_path {
        if let Err(err) = fresh.save_to_file(path) {
            tracing::warn!(
                path = %path.display(),
                error = %err,
                "failed persisting refreshed NRD cache to disk"
            );
        }
    }
    let mut guard = nrd_cache.write().unwrap_or_else(|e| e.into_inner());
    *guard = fresh;
    Ok(stats)
}
