//! Shared ETW callback context, honeypot handle tracker, and registry KCB cache.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use ledr_proto::SensorEvent;

use crate::dns_cache::DnsResolutionCache;
use crate::path_norm::DosVolumeMap;

use super::ProcessPackageInfo;
use super::cmdline_correlator::ProcessCommandLineCorrelator;
use super::file_canary::CanaryMatcher;
use super::session::PackageAwareEventSinkFn;

const MAX_TRACKED_HONEYPOT_HANDLES: usize = 512;

struct TrackedHoneypotHandle {
    target_path: String,
    triggered: bool,
}

#[derive(Default)]
pub(super) struct HoneypotHandleTracker {
    by_file_object: HashMap<u64, TrackedHoneypotHandle>,
    fifo_order: VecDeque<u64>,
}

impl HoneypotHandleTracker {
    pub(super) fn track_open(&mut self, file_object: u64, target_path: String) -> bool {
        if file_object == 0 {
            return !self.by_file_object.is_empty();
        }
        if let Some(existing) = self.by_file_object.get_mut(&file_object) {
            existing.target_path = target_path;
            existing.triggered = false;
            return true;
        }
        while self.by_file_object.len() >= MAX_TRACKED_HONEYPOT_HANDLES {
            let Some(oldest) = self.fifo_order.pop_front() else {
                break;
            };
            self.by_file_object.remove(&oldest);
        }
        self.fifo_order.push_back(file_object);
        self.by_file_object.insert(
            file_object,
            TrackedHoneypotHandle {
                target_path,
                triggered: false,
            },
        );
        true
    }

    pub(super) fn trigger_write_or_delete(&mut self, file_object: u64) -> Option<String> {
        let entry = self.by_file_object.get_mut(&file_object)?;
        if entry.triggered {
            return None;
        }
        entry.triggered = true;
        Some(entry.target_path.clone())
    }

    pub(super) fn close_handle(&mut self, file_object: u64) -> bool {
        self.by_file_object.remove(&file_object);
        !self.by_file_object.is_empty()
    }
}

pub(super) struct EtwCallbackContext {
    pub(super) sink: PackageAwareEventSinkFn,
    pub(super) dns_cache: Mutex<DnsResolutionCache>,
    pub(super) volume_map: DosVolumeMap,
    pub(super) canary_matcher: Arc<RwLock<CanaryMatcher>>,
    pub(super) honeypot_handles: Mutex<HoneypotHandleTracker>,
    pub(super) has_honeypot_handles: AtomicBool,
    pub(super) registry_kcb_names: Mutex<HashMap<u64, String>>,
    pub(super) cmdline_correlator: Arc<Mutex<ProcessCommandLineCorrelator>>,
    pub(super) aux_active: Arc<AtomicBool>,
    pub(super) stop_requested: Arc<AtomicBool>,
    pub(super) session_name_nul: Vec<u16>,
}

/// Lightweight ETW callback context for the auxiliary `EVENT_TRACE_SYSTEM_LOGGER_MODE`
/// (`EVENT_TRACE_FLAG_PROCESS`) session supplying kernel-captured `CommandLine` values.
pub(super) struct AuxSystemProcessContext {
    pub(super) sink: PackageAwareEventSinkFn,
    pub(super) cmdline_correlator: Arc<Mutex<ProcessCommandLineCorrelator>>,
    pub(super) stop_requested: Arc<AtomicBool>,
    pub(super) aux_active: Arc<AtomicBool>,
    pub(super) session_name_nul: Vec<u16>,
}

impl AuxSystemProcessContext {
    /// Emits an enriched `ProcessStart` event directly to the bounded downstream sink.
    ///
    /// Mirrors [`EtwCallbackContext::dispatch_event`]: delegates backpressure to the
    /// downstream sink (in production, `TwoLaneSender::blocking_send` on the non-dropping
    /// `L-10` high-priority lane), and marks `stop_requested` / clears `aux_active` only
    /// when the downstream sink closes.
    pub(super) fn dispatch_event_with_package(
        &self,
        event: SensorEvent,
        package: ProcessPackageInfo,
    ) -> bool {
        if self.stop_requested.load(Ordering::Acquire) {
            return false;
        }
        if !(self.sink)(event, package) {
            self.stop_requested.store(true, Ordering::Release);
            self.aux_active.store(false, Ordering::Release);
            return false;
        }
        true
    }
}

/// Bound on the cached `KeyObject` -> key-path map for autorun registry keys.
/// Only autorun paths are cached, so this stays small; on overflow the cache is
/// cleared rather than grown to keep worst-case memory bounded.
const REGISTRY_KCB_CACHE_CAPACITY: usize = 4096;

impl EtwCallbackContext {
    /// Emits a decoded event directly to the bounded downstream sink.
    ///
    /// Marks `stop_requested` only once the sink returns `false` (downstream receiver closed)
    /// or if cancellation was already requested.
    pub(super) fn dispatch_event(&self, event: SensorEvent) -> bool {
        self.dispatch_event_with_package(event, ProcessPackageInfo::default())
    }

    pub(super) fn dispatch_event_with_package(
        &self,
        event: SensorEvent,
        package: ProcessPackageInfo,
    ) -> bool {
        if self.stop_requested.load(Ordering::Acquire) {
            return false;
        }
        if !(self.sink)(event, package) {
            self.stop_requested.store(true, Ordering::Release);
            return false;
        }
        true
    }

    pub(super) fn track_honeypot_handle(&self, file_object: u64, target_path: String) {
        let mut tracker = self
            .honeypot_handles
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let non_empty = tracker.track_open(file_object, target_path);
        self.has_honeypot_handles.store(non_empty, Ordering::Release);
    }

    pub(super) fn trigger_honeypot_handle(&self, file_object: u64) -> Option<String> {
        let mut tracker = self
            .honeypot_handles
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        tracker.trigger_write_or_delete(file_object)
    }

    pub(super) fn close_honeypot_handle(&self, file_object: u64) {
        let mut tracker = self
            .honeypot_handles
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let non_empty = tracker.close_handle(file_object);
        self.has_honeypot_handles.store(non_empty, Ordering::Release);
    }

    pub(super) fn evict_dns_pid(&self, pid: u32) {
        self.dns_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove_pid(pid);
    }

    pub(super) fn record_dns_resolution(
        &self,
        pid: u32,
        query_name: &str,
        resolved_ips: &[IpAddr],
        timestamp_ms: i64,
    ) {
        if !resolved_ips.is_empty() {
            self.dns_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert_resolution_for_pid(pid, query_name, resolved_ips, timestamp_ms);
        }
    }

    pub(super) fn resolve_network_domain_hint(&self, pid: u32, dst_ip: &IpAddr) -> Option<String> {
        self.dns_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .lookup_domain_for_pid(pid, dst_ip)
    }
}

/// Caches an autorun registry key's KCB pointer -> path so write events whose
/// `KeyName` arrives empty (uncached KCB name) can still be attributed.
pub(super) fn remember_registry_key(cache: &Mutex<HashMap<u64, String>>, key_object: u64, key_name: &str) {
    let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    if cache.len() >= REGISTRY_KCB_CACHE_CAPACITY {
        cache.clear();
    }
    cache.insert(key_object, key_name.to_owned());
}

pub(super) fn lookup_registry_key(cache: &Mutex<HashMap<u64, String>>, key_object: u64) -> Option<String> {
    cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&key_object)
        .cloned()
}

/// Removes and returns the cached path for `key_object`. Called on DeleteKey (the KCB
/// stops accepting writes), on CloseKey (the pointer may be recycled for a different
/// key), and whenever an event proves the object is bound to an unmonitored key.
pub(super) fn take_registry_key(cache: &Mutex<HashMap<u64, String>>, key_object: u64) -> Option<String> {
    cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&key_object)
}
