//! Thread-safe WFP dynamic firewall engine coordinator (`L-03`, `AUTO-04`).

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};

use super::backend::{LiveWfpBackend, WfpBackend};
use super::net_events::{WfpDropSinkFn, WfpFilterMeta};
use super::spec::build_wfp_filter_specs;

struct WfpEngineState {
    backend: Box<dyn WfpBackend>,
    next_handle: u64,
    handles: HashMap<u64, Vec<u64>>,
}

/// Thread-safe WFP dynamic firewall engine wrapping dual-stack IPv4/IPv6 filter pairs under a
/// single opaque `u64` rule handle (`L-03`, `AUTO-04`).
pub struct WfpDynamicEngine {
    state: Mutex<WfpEngineState>,
    // Separate lock from `state` so BFE net-event callbacks never deadlock against BFE writes.
    filter_index: Arc<RwLock<HashMap<u64, WfpFilterMeta>>>,
}

impl std::fmt::Debug for WfpDynamicEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self
            .state
            .lock()
            .map(|s| s.handles.len())
            .unwrap_or(0);
        f.debug_struct("WfpDynamicEngine")
            .field("active_handles", &count)
            .finish()
    }
}

impl WfpDynamicEngine {
    /// Opens a live Windows WFP dynamic session (`FWPM_SESSION_FLAG_DYNAMIC`) and registers
    /// LocalEDR's dedicated SubLayer.
    pub fn open_dynamic() -> Result<Self, String> {
        let backend = LiveWfpBackend::open_dynamic()?;
        Self::from_backend(Box::new(backend))
    }

    /// Constructs a [`WfpDynamicEngine`] around an injectable [`WfpBackend`] (for tests).
    pub fn from_backend(backend: Box<dyn WfpBackend>) -> Result<Self, String> {
        if !backend.is_dynamic_session() {
            return Err(
                "refusing non-dynamic WFP session: FWPM_SESSION_FLAG_DYNAMIC is mandatory (AUTO-04)"
                    .to_string(),
            );
        }
        Ok(Self {
            state: Mutex::new(WfpEngineState {
                backend,
                next_handle: 1,
                handles: HashMap::new(),
            }),
            filter_index: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Subscribes to WFP net-event drops for active LocalEDR block filters (`BUG_0001`).
    pub fn set_drop_sink(&self, sink: WfpDropSinkFn) -> Result<(), String> {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .backend
            .set_drop_sink(Arc::clone(&self.filter_index), Some(sink))
    }

    /// Unsubscribes any active WFP net-event drop sink.
    pub fn clear_drop_sink(&self) -> Result<(), String> {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .backend
            .set_drop_sink(Arc::clone(&self.filter_index), None)
    }

    /// Atomically adds a dynamic outbound Block or Permit rule for `exe_path` (single-stack when
    /// `remote_ip` is `Some`, dual-stack IPv4+IPv6 inside one WFP transaction when `remote_ip` is
    /// `None`) and returns an opaque non-zero handle `u64`.
    pub fn add_app_rule(
        &self,
        exe_path: &Path,
        remote_ip: Option<IpAddr>,
        allow: bool,
    ) -> Result<u64, String> {
        let specs = build_wfp_filter_specs(exe_path, remote_ip, allow)?;
        let exe_path_norm = specs[0].exe_path.clone();
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());

        guard.backend.begin_transaction()?;
        let mut os_filter_ids = Vec::with_capacity(specs.len());
        for spec in &specs {
            match guard.backend.add_filter(spec) {
                Ok(id) => os_filter_ids.push(id),
                Err(err) => {
                    guard.backend.abort_transaction();
                    return Err(err);
                }
            }
        }
        if let Err(err) = guard.backend.commit_transaction() {
            guard.backend.abort_transaction();
            return Err(err);
        }

        let handle = guard.next_handle;
        guard.next_handle = guard.next_handle.checked_add(1).unwrap_or(1);
        if guard.next_handle == 0 {
            guard.next_handle = 1;
        }
        {
            let mut index = self.filter_index.write().unwrap_or_else(|e| e.into_inner());
            let meta = WfpFilterMeta {
                rule_handle: handle,
                exe_path: exe_path_norm,
                allow,
            };
            for &os_id in &os_filter_ids {
                index.insert(os_id, meta.clone());
            }
        }
        guard.handles.insert(handle, os_filter_ids);
        Ok(handle)
    }

    /// Atomically deletes all OS WFP filters associated with `handle_id`.
    pub fn remove_rule(&self, handle_id: u64) -> Result<(), String> {
        if handle_id == 0 {
            return Err("invalid WFP rule handle 0".to_string());
        }
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let Some(os_ids) = guard.handles.get(&handle_id).cloned() else {
            return Err(format!("unknown WFP rule handle {handle_id}"));
        };

        guard.backend.begin_transaction()?;
        for os_id in &os_ids {
            if let Err(err) = guard.backend.delete_filter(*os_id) {
                guard.backend.abort_transaction();
                return Err(err);
            }
        }
        if let Err(err) = guard.backend.commit_transaction() {
            guard.backend.abort_transaction();
            return Err(err);
        }

        guard.handles.remove(&handle_id);
        {
            let mut index = self.filter_index.write().unwrap_or_else(|e| e.into_inner());
            for os_id in &os_ids {
                index.remove(os_id);
            }
        }
        Ok(())
    }

    /// Returns a snapshot of indexed filter metadata for `os_filter_id` (diagnostics/tests).
    pub fn filter_meta(&self, os_filter_id: u64) -> Option<WfpFilterMeta> {
        self.filter_index
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&os_filter_id)
            .cloned()
    }

    /// Returns the number of currently active opaque rule handles.
    pub fn active_handle_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .handles
            .len()
    }

    /// Returns the OS filter IDs currently mapped to `handle_id` (diagnostics/tests).
    pub fn os_filter_ids_for_handle(&self, handle_id: u64) -> Option<Vec<u64>> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .handles
            .get(&handle_id)
            .cloned()
    }
}
