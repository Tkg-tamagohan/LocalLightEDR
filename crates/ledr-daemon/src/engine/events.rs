use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::atomic::Ordering;

use ledr_proto::{
    is_never_suspend_process, AlertRecord, AlertSeverity, AlertStatus, CanaryCategory, EventLane,
    ProcessIdentity, RuleScope, SensorEvent,
};
use ledr_rules::{
    classify_outbound_risk, is_allowed_by_rules, BinaryIdentity, EventContext, OutboundRiskClass,
};
use ledr_store::StoreError;
use uuid::Uuid;

use crate::firewall::{WfpFilterOrigin, WfpRuleManager};
use crate::process_table::ProcessStartResolution;

use super::{current_unix_ms, event_timestamp_ms, DaemonEngine};

pub(super) struct DnsCorrelationUpdate {
    pub(super) instance_id: String,
    pub(super) exe_key: String,
    pub(super) accepted_ips: Vec<IpAddr>,
}

pub(super) struct SeedProcessStartOutcome {
    pub(super) resolved_active_id: Option<String>,
    pub(super) motw_candidate: Option<(String, String)>,
}

struct PreparedCanaryBackfill {
    ident: ProcessIdentity,
    create_time_100ns: u64,
    existing_ppid: u32,
    exe_path: String,
    command_line: String,
    res: ProcessStartResolution,
}

impl DaemonEngine {
    fn attach_motw_to_proc_ctx(
        &self,
        instance_id: Option<&str>,
        proc_ctx: &mut ResolvedProcessContext,
        motw: super::motw::MotwAttribution,
    ) {
        let motw_source_str = motw.stage.as_str().to_string();
        if let Some(inst_id) = instance_id {
            self.process_table
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .set_motw_metadata(
                    inst_id,
                    motw.origin_url.clone(),
                    motw_source_str.clone(),
                    motw.referrer_url.clone(),
                    motw.frame_url.clone(),
                    motw.zone_id,
                );
        }
        if proc_ctx.skip_store_ingest {
            if let Some(inst_id) = instance_id {
                if let Err(err) = self.store.update_process_motw_metadata(
                    inst_id,
                    Some(&motw.origin_url),
                    motw.sha256.as_deref(),
                ) {
                    tracing::warn!(
                        process_instance_id = %inst_id,
                        error = %err,
                        "failed backfilling MOTW metadata on skip_store_ingest event"
                    );
                }
            }
        }
        proc_ctx.origin_url = Some(motw.origin_url);
        proc_ctx.motw_source = Some(motw_source_str);
        proc_ctx.motw_referrer = motw.referrer_url;
        proc_ctx.motw_frame_url = motw.frame_url;
        proc_ctx.motw_zone_id = motw.zone_id;
        proc_ctx.proc_sha256 = motw.sha256;
    }

    pub(super) fn apply_late_motw_attribution(&self, late: super::motw::LateMotwAttribution) {
        let mut persist_instance_ids: Vec<String> = Vec::new();
        let mut active_instances: Vec<(String, u32)> = Vec::new();
        {
            let mut table = self
                .process_table
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            for inst_id in &late.instance_ids {
                if let Some((exe_path, pid)) = table.set_motw_metadata_if_active(
                    inst_id,
                    late.attribution.origin_url.clone(),
                    late.attribution.stage.as_str().to_string(),
                    late.attribution.referrer_url.clone(),
                    late.attribution.frame_url.clone(),
                    late.attribution.zone_id,
                ) {
                    persist_instance_ids.push(inst_id.clone());
                    active_instances.push((exe_path, pid));
                } else if table
                    .get_by_instance_id(inst_id)
                    .is_none_or(|entry| entry.origin_url.is_none())
                {
                    // Exited or evicted process without prior `origin_url`: still backfill
                    // SQLite history (`COALESCE`, non-overwriting) without applying active
                    // WFP blocks or mutating active outbound classification.
                    persist_instance_ids.push(inst_id.clone());
                }
            }
        }
        if persist_instance_ids.is_empty() && active_instances.is_empty() {
            return;
        }

        for inst_id in &persist_instance_ids {
            match self.store.update_process_motw_metadata(
                inst_id,
                Some(&late.attribution.origin_url),
                late.attribution.sha256.as_deref(),
            ) {
                Ok(true) => {}
                Ok(false) => {
                    tracing::debug!(
                        process_instance_id = %inst_id,
                        "delayed MOTW backfill found no matching process row in SQLite store"
                    );
                }
                Err(err) => {
                    tracing::warn!(
                        process_instance_id = %inst_id,
                        error = %err,
                        "failed backfilling delayed MOTW metadata into SQLite store"
                    );
                }
            }
        }

        let mut promoted_exe_keys: HashSet<String> = HashSet::new();
        for (exe_path, pid) in active_instances {
            if self.is_self_process(pid, &exe_path) {
                self.outbound_classifier.mark_protected_os(pid);
                continue;
            }
            // Clear any pre-MOTW steady-state outbound classification so subsequent connects
            // re-enter the high-priority enforcement path rather than staying on telemetry.
            self.outbound_classifier.remove_pid(pid);

            if self.config.outbound_firewall_enabled {
                let exe_key = WfpRuleManager::exe_key(&exe_path);
                if promoted_exe_keys.insert(exe_key) {
                    self.maybe_apply_preemptive_wfp_block_with_motw(&exe_path, true);
                }
            }
        }
    }

    pub(super) fn process_seed_process_start(&self, event: &SensorEvent) -> SeedProcessStartOutcome {
        let now_ms = current_unix_ms();
        let event_ts_ms = event_timestamp_ms(event, now_ms);
        let proc_ctx = self.resolve_process_context(event, event_ts_ms);

        let motw_candidate = if let SensorEvent::ProcessStart { identity, .. } = event {
            if proc_ctx.origin_url.is_none()
                && proc_ctx.exited_at_ms.is_none()
                && !proc_ctx.skip_launch_guards
            {
                match (
                    proc_ctx.proc_instance_id.as_deref(),
                    proc_ctx.proc_exe_path.as_deref(),
                ) {
                    (Some(inst_id), Some(effective_exe))
                        if !self.is_self_process(identity.pid, effective_exe) =>
                    {
                        Self::should_schedule_process_motw(
                            effective_exe,
                            proc_ctx.exited_at_ms,
                            proc_ctx.skip_launch_guards,
                        )
                        .map(|normalized_exe| (inst_id.to_string(), normalized_exe))
                    }
                    _ => None,
                }
            } else {
                None
            }
        } else {
            None
        };

        let _ = self.finish_event_processing(event, event.default_lane(), event_ts_ms, proc_ctx);
        let resolved_active_id = if let SensorEvent::ProcessStart { identity, .. } = event {
            let table = self
                .process_table
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = table.lookup_by_pid(identity.pid) {
                if entry.exited_at_ms.is_none() {
                    Some(entry.instance_id.clone())
                } else {
                    Some(identity.instance_id())
                }
            } else {
                Some(identity.instance_id())
            }
        } else {
            None
        };
        SeedProcessStartOutcome {
            resolved_active_id,
            motw_candidate,
        }
    }

    pub(super) async fn process_event_with_lane_async(
        &self,
        event: &SensorEvent,
        lane: EventLane,
    ) -> Option<DnsCorrelationUpdate> {
        if let SensorEvent::CanaryFileAccess {
            category: CanaryCategory::Honeypot,
            is_write_or_delete: false,
            ..
        } = event
        {
            // L-06: Read-only honeypot opens are ignored to avoid SearchIndexer/backup false positives.
            self.high_priority_processed.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        let now_ms = current_unix_ms();
        let event_ts_ms = event_timestamp_ms(event, now_ms);

        let mut proc_ctx = self.resolve_process_context(event, event_ts_ms);

        if let SensorEvent::ProcessStart { identity, .. } = event {
            if proc_ctx.origin_url.is_none()
                && proc_ctx.exited_at_ms.is_none()
                && !proc_ctx.skip_launch_guards
            {
                if let Some(effective_exe) = proc_ctx.proc_exe_path.as_deref() {
                    if !self.is_self_process(identity.pid, effective_exe) {
                        if let Some(motw) = self
                            .resolve_process_motw_budgeted(
                                proc_ctx.proc_instance_id.as_deref(),
                                effective_exe,
                                proc_ctx.exited_at_ms,
                                proc_ctx.skip_launch_guards,
                            )
                            .await
                        {
                            let inst_id = proc_ctx.proc_instance_id.clone();
                            self.attach_motw_to_proc_ctx(inst_id.as_deref(), &mut proc_ctx, motw);
                        }
                    }
                }
            }
        }

        if matches!(event, SensorEvent::CanaryFileAccess { .. }) {
            self.backfill_canary_process_context_if_missing_async(
                event,
                &mut proc_ctx,
                event_ts_ms,
            )
            .await;
            self.handle_canary_file_access(event, &proc_ctx, event_ts_ms);
            self.high_priority_processed.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        self.finish_event_processing(event, lane, event_ts_ms, proc_ctx)
    }

    #[cfg(test)]
    pub(super) fn process_event_with_lane(
        &self,
        event: &SensorEvent,
        lane: EventLane,
    ) -> Option<DnsCorrelationUpdate> {
        if let SensorEvent::CanaryFileAccess {
            category: CanaryCategory::Honeypot,
            is_write_or_delete: false,
            ..
        } = event
        {
            self.high_priority_processed.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        let now_ms = current_unix_ms();
        let event_ts_ms = event_timestamp_ms(event, now_ms);
        let mut proc_ctx = self.resolve_process_context(event, event_ts_ms);

        if let SensorEvent::ProcessStart { identity, .. } = event {
            if proc_ctx.origin_url.is_none()
                && proc_ctx.exited_at_ms.is_none()
                && !proc_ctx.skip_launch_guards
            {
                if let Some(effective_exe) = proc_ctx.proc_exe_path.as_deref() {
                    if !self.is_self_process(identity.pid, effective_exe) {
                        if let Some(motw) = self.resolve_process_motw(
                            effective_exe,
                            proc_ctx.exited_at_ms,
                            proc_ctx.skip_launch_guards,
                        ) {
                            let inst_id = proc_ctx.proc_instance_id.clone();
                            self.attach_motw_to_proc_ctx(inst_id.as_deref(), &mut proc_ctx, motw);
                        }
                    }
                }
            }
        }

        if matches!(event, SensorEvent::CanaryFileAccess { .. }) {
            if let Some((pid, prepared)) =
                self.prepare_canary_backfill_sync(event, &proc_ctx, event_ts_ms)
            {
                if proc_ctx.origin_url.is_none()
                    && prepared.res.exited_at_ms.is_none()
                    && !prepared.exe_path.is_empty()
                    && !prepared.res.skip_launch_guards
                    && !self.is_self_process(pid, &prepared.exe_path)
                {
                    if let Some(motw) = self.resolve_process_motw(
                        &prepared.exe_path,
                        prepared.res.exited_at_ms,
                        prepared.res.skip_launch_guards,
                    ) {
                        self.attach_motw_to_proc_ctx(
                            Some(&prepared.res.instance_id),
                            &mut proc_ctx,
                            motw,
                        );
                    }
                }
                self.finalize_canary_backfill(pid, &mut proc_ctx, prepared);
            }
            self.handle_canary_file_access(event, &proc_ctx, event_ts_ms);
            self.high_priority_processed.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        self.finish_event_processing(event, lane, event_ts_ms, proc_ctx)
    }

    fn finish_event_processing(
        &self,
        event: &SensorEvent,
        lane: EventLane,
        event_ts_ms: i64,
        proc_ctx: ResolvedProcessContext,
    ) -> Option<DnsCorrelationUpdate> {
        let effective_event = proc_ctx.effective_process_start.as_ref().unwrap_or(event);
        let ctx = EventContext::with_parent(
            effective_event,
            proc_ctx.parent_exe_path.as_deref(),
            proc_ctx.parent_command_line.as_deref(),
        );

        if self
            .pruner
            .should_prune_with_image(&ctx, proc_ctx.proc_exe_path.as_deref())
        {
            self.pruned_events.fetch_add(1, Ordering::Relaxed);
        } else if proc_ctx.should_evaluate_sigma {
            let matches = self
                .sigma
                .evaluate_with_image(&ctx, proc_ctx.proc_exe_path.as_deref());
            for m in matches {
                if let Some(ref inst_id) = proc_ctx.proc_instance_id {
                    // Distinct script bodies evaluated in the same process must each be able to
                    // fire an alert; deduplicate per (instance, rule, content fingerprint).
                    let dedup_key = match event {
                        SensorEvent::ScriptEvaluated { script_content, .. } => {
                            let mut h = DefaultHasher::new();
                            script_content.hash(&mut h);
                            format!("{}:{:x}", m.rule_id, h.finish())
                        }
                        _ => m.rule_id.clone(),
                    };
                    if !self.is_new_rule_alert(inst_id, &dedup_key) {
                        continue;
                    }
                }
                let context_json = serde_json::json!({
                    "event": effective_event,
                    "parent_exe_path": proc_ctx.parent_exe_path,
                    "parent_command_line": proc_ctx.parent_command_line,
                    "matched_fields": m.matched_fields,
                    "origin_url": proc_ctx.origin_url,
                    "motw_source": proc_ctx.motw_source,
                    "motw_referrer": proc_ctx.motw_referrer,
                    "motw_frame_url": proc_ctx.motw_frame_url,
                    "motw_zone_id": proc_ctx.motw_zone_id,
                })
                .to_string();

                let alert = AlertRecord {
                    alert_id: Uuid::new_v4().to_string(),
                    timestamp_ms: event_ts_ms,
                    severity: m.severity,
                    source_layer: "LAYER_2_RULES".to_string(),
                    rule_id: m.rule_id,
                    title: m.title,
                    process_instance_id: proc_ctx.proc_instance_id.clone(),
                    process_suspended: false,
                    status: AlertStatus::Pending,
                    context_json,
                    resolved_at_ms: None,
                };
                let record_result = if self.fail_record_alert_for_test.load(Ordering::Acquire) {
            Err(StoreError::InvalidValue {
                field: "alerts.test_injection",
                value: "injected record_alert failure".to_string(),
            })
        } else {
            self.store.record_alert(&alert)
        };

        if let Err(err) = record_result {
                    tracing::warn!(error = %err, rule_id = %alert.rule_id, "failed to record Sigma alert");
                } else {
                    self.alerts_emitted.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        let is_nrd = if let SensorEvent::DnsQuery { query_name, .. } = event {
            self.assess_domain(query_name).is_nrd
        } else {
            false
        };

        let mut flush_now = false;
        let mut dns_correlation: Option<DnsCorrelationUpdate> = None;
        let action = match event {
            SensorEvent::ProcessStart {
                identity, exe_path, ..
            } => {
                if proc_ctx.exited_at_ms.is_none() && !proc_ctx.skip_launch_guards {
                    let effective_exe = proc_ctx
                        .proc_exe_path
                        .as_deref()
                        .unwrap_or(exe_path.as_str());
                    self.apply_process_launch_guards(
                        identity.pid,
                        proc_ctx.proc_instance_id.as_deref(),
                        effective_exe,
                        proc_ctx.origin_url.is_some(),
                    );
                }
                "OBSERVED"
            }
            SensorEvent::ProcessStop { pid, .. } => {
                if let Some(ref inst_id) = proc_ctx.proc_instance_id {
                    self.outbound_classifier.remove_pid(*pid);
                    self.verified_app_wide_allows
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(inst_id);
                    self.process_dns_history
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove_process(inst_id);
                    let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                    let was_once_allowed = fw.on_process_stop(inst_id);
                    if self.config.outbound_firewall_enabled {
                        if let Some(ref exe_path) = proc_ctx.proc_exe_path {
                            let exe_k = WfpRuleManager::exe_key(exe_path);
                            let is_startup_pinned = fw.is_startup_preemptive(exe_path);
                            let is_preemptive = fw
                                .active_app_block(exe_path)
                                .is_some_and(|(_, origin)| origin == WfpFilterOrigin::Preemptive);
                            let has_any_filter = fw.has_any_app_filter(exe_path);
                            let has_other_once_allowed = fw.has_once_allowed_for_exe(&exe_k);
                            drop(fw);

                            if is_preemptive && !is_startup_pinned {
                                let still_active = self
                                    .process_table
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .has_active_exe_key(&exe_k);
                                if !still_active {
                                    let mut fw =
                                        self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                                    fw.remove_preemptive_block_if_unused(exe_path, &*self.defense);
                                }
                            } else if was_once_allowed
                                && !has_any_filter
                                && !has_other_once_allowed
                            {
                                let should_restore = is_startup_pinned
                                    || self
                                        .process_table
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner())
                                        .has_active_exe_key(&exe_k);
                                if should_restore {
                                    self.maybe_apply_preemptive_wfp_block(exe_path);
                                }
                            }
                        }
                    }
                }
                "OBSERVED"
            }
            SensorEvent::DnsQuery {
                pid,
                query_name,
                resolved_ips,
                ..
            } => {
                if !resolved_ips.is_empty() {
                    let is_self_dns = proc_ctx
                        .proc_exe_path
                        .as_deref()
                        .is_some_and(|exe| self.is_self_process(*pid, exe));
                    let exe_k_opt = proc_ctx
                        .proc_exe_path
                        .as_deref()
                        .map(WfpRuleManager::exe_key);
                    let accepted_ips: Option<Vec<IpAddr>> =
                        if let Some(ref inst_id) = proc_ctx.proc_instance_id {
                            let accepted = self
                                .process_dns_history
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .record_for_exe(
                                    inst_id,
                                    exe_k_opt.as_deref().unwrap_or(""),
                                    query_name,
                                    resolved_ips,
                                    event_ts_ms,
                                );
                            if let Some(exe_k) = exe_k_opt {
                                if !accepted.is_empty() {
                                    dns_correlation = Some(DnsCorrelationUpdate {
                                        instance_id: inst_id.clone(),
                                        exe_key: exe_k,
                                        accepted_ips: accepted.clone(),
                                    });
                                }
                            }
                            Some(accepted)
                        } else {
                            None
                        };
                    if self.config.outbound_firewall_enabled && !is_self_dns {
                        match accepted_ips.as_deref() {
                            Some([]) => {}
                            Some(ips) => {
                                self.prematerialize_domain_wfp_filters(query_name, ips, &proc_ctx);
                            }
                            None => {
                                self.prematerialize_domain_wfp_filters(
                                    query_name,
                                    resolved_ips,
                                    &proc_ctx,
                                );
                            }
                        }
                    }
                }
                "OBSERVED"
            }
            SensorEvent::NetworkConnect { .. } if self.config.outbound_firewall_enabled => {
                let (act, emitted_alert) =
                    self.handle_network_connect(event, &proc_ctx, event_ts_ms);
                flush_now = emitted_alert;
                act
            }
            _ => "OBSERVED",
        };

        if !proc_ctx.skip_store_ingest {
            if let Err(err) = self.store.ingest_event_with_process_metadata(
                effective_event,
                proc_ctx.store_hint.as_deref(),
                proc_ctx.exited_at_ms,
                proc_ctx
                    .superseded_exit
                    .as_ref()
                    .map(|(id, exit_ms)| (id.as_str(), *exit_ms)),
                proc_ctx.origin_url.as_deref(),
                proc_ctx.proc_sha256.as_deref(),
                is_nrd,
                action,
            ) {
                tracing::warn!(error = %err, "failed to ingest event into SQLite store");
            } else if flush_now {
                if let Err(err) = self.store.flush_batch() {
                    tracing::warn!(error = %err, "failed to flush network alert telemetry batch");
                }
            }
        }

        match lane {
            EventLane::HighPriority => {
                self.high_priority_processed.fetch_add(1, Ordering::Relaxed);
            }
            EventLane::Telemetry => {
                self.telemetry_processed.fetch_add(1, Ordering::Relaxed);
            }
        }

        dns_correlation
    }

    pub(super) fn record_alert_checked(&self, alert: &AlertRecord) -> Result<(), StoreError> {
        if self.fail_record_alert_for_test.load(Ordering::Acquire) {
            Err(StoreError::InvalidValue {
                field: "alerts.test_injection",
                value: "injected record_alert failure".to_string(),
            })
        } else {
            self.store.record_alert(alert)
        }
    }

    /// On-demand PID lookup fallback for ETW cross-provider ordering races (`Kernel-File`
    /// delivering a canary access milliseconds before `Kernel-Process` delivers `ProcessStart`).
    async fn backfill_canary_process_context_if_missing_async(
        &self,
        event: &SensorEvent,
        proc_ctx: &mut ResolvedProcessContext,
        event_ts_ms: i64,
    ) {
        let Some((pid, prepared)) = self.prepare_canary_backfill_sync(event, proc_ctx, event_ts_ms)
        else {
            return;
        };
        if proc_ctx.origin_url.is_none()
            && prepared.res.exited_at_ms.is_none()
            && !prepared.exe_path.is_empty()
            && !prepared.res.skip_launch_guards
            && !self.is_self_process(pid, &prepared.exe_path)
        {
            if let Some(motw) = self
                .resolve_process_motw_budgeted(
                    Some(&prepared.res.instance_id),
                    &prepared.exe_path,
                    prepared.res.exited_at_ms,
                    prepared.res.skip_launch_guards,
                )
                .await
            {
                self.attach_motw_to_proc_ctx(
                    Some(&prepared.res.instance_id),
                    proc_ctx,
                    motw,
                );
            }
        }
        self.finalize_canary_backfill(pid, proc_ctx, prepared);
    }

    fn prepare_canary_backfill_sync(
        &self,
        event: &SensorEvent,
        proc_ctx: &ResolvedProcessContext,
        event_ts_ms: i64,
    ) -> Option<(u32, PreparedCanaryBackfill)> {
        let SensorEvent::CanaryFileAccess { pid, .. } = event else {
            return None;
        };
        let needs_create_time = proc_ctx
            .proc_identity
            .is_none_or(|id| id.create_time_100ns == 0);
        let needs_exe_path = proc_ctx
            .proc_exe_path
            .as_deref()
            .is_none_or(|p| p.trim().is_empty());
        if !needs_create_time && !needs_exe_path {
            return None;
        }

        let live = self.live_process_inspector.inspect_live_process(*pid)?;
        if live.create_time_100ns == 0 {
            return None;
        }
        // Guard against PID reuse (`BUG_0001`): if the live OS process at `pid` was created
        // strictly after the canary event timestamp, it cannot be the original accessor.
        let live_created_ms = super::filetime_100ns_to_unix_ms(live.create_time_100ns, i64::MAX);
        if live_created_ms > event_ts_ms {
            tracing::debug!(
                pid = *pid,
                live_created_ms,
                event_ts_ms,
                "skipping canary process backfill because live process started after event timestamp (possible PID reuse)"
            );
            return None;
        }

        // Guard against PID reuse: if we already have a non-zero creation timestamp for this
        // process context, never overwrite it with a different live process that reused the PID.
        if let Some(existing_id) = proc_ctx.proc_identity {
            if existing_id.create_time_100ns != 0
                && existing_id.create_time_100ns != live.create_time_100ns
            {
                return None;
            }
        }

        let existing_exe_opt = proc_ctx
            .proc_exe_path
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let live_exe_opt = live
            .exe_path
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());

        // If the table already had a non-empty exe_path (e.g., synthetic PID with zero timestamp),
        // only backfill when the live OS process reports a matching executable path (fail closed
        // if the live image path cannot be queried).
        if let Some(existing_exe) = existing_exe_opt {
            let live_exe = live_exe_opt?;
            if !existing_exe
                .replace('/', "\\")
                .eq_ignore_ascii_case(&live_exe.replace('/', "\\"))
            {
                return None;
            }
        }

        let existing_cmd_opt = proc_ctx
            .proc_command_line
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let live_cmd_opt = live
            .command_line
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());

        let gained_create_time = proc_ctx
            .proc_identity
            .is_none_or(|id| id.create_time_100ns == 0);
        let gained_exe_path = existing_exe_opt.is_none() && live_exe_opt.is_some();
        let gained_command_line = existing_cmd_opt.is_none() && live_cmd_opt.is_some();
        if !gained_create_time && !gained_exe_path && !gained_command_line {
            return None;
        }

        let exe_path = existing_exe_opt
            .or(live_exe_opt)
            .map(str::to_string)
            .unwrap_or_default();
        let command_line = existing_cmd_opt
            .or(live_cmd_opt)
            .map(str::to_string)
            .unwrap_or_default();

        // Record the live process's actual creation timestamp (`live_created_ms <= event_ts_ms`)
        // so `ActiveProcessTable::lookup_by_pid_at` matches events and child ProcessStarts
        // occurring between process creation and this canary event.
        let backfilled_created_ms =
            super::filetime_100ns_to_unix_ms(live.create_time_100ns, event_ts_ms);
        let ident = ProcessIdentity::new(*pid, live.create_time_100ns);
        let ident_instance_id = ident.instance_id();
        let (existing_ppid, res) = {
            let mut table = self
                .process_table
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let existing_ppid = table
                .get_by_instance_id(&ident_instance_id)
                .or_else(|| {
                    proc_ctx
                        .proc_instance_id
                        .as_deref()
                        .and_then(|id| table.get_by_instance_id(id))
                })
                .map(|entry| entry.ppid)
                .unwrap_or(0);
            let res = table.on_process_start(
                ident,
                existing_ppid,
                exe_path.clone(),
                command_line.clone(),
                None,
                backfilled_created_ms,
            );
            (existing_ppid, res)
        };
        if res.superseded_exit.is_some() || !res.evicted_instance_ids.is_empty() {
            let mut cache = self
                .verified_app_wide_allows
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some((ref prev_id, _)) = res.superseded_exit {
                cache.remove(prev_id);
            }
            for evicted_id in &res.evicted_instance_ids {
                cache.remove(evicted_id);
            }
        }

        Some((
            *pid,
            PreparedCanaryBackfill {
                ident,
                create_time_100ns: live.create_time_100ns,
                existing_ppid,
                exe_path,
                command_line,
                res,
            },
        ))
    }

    fn apply_process_launch_guards(
        &self,
        pid: u32,
        instance_id: Option<&str>,
        effective_exe: &str,
        has_motw: bool,
    ) {
        let is_self = self.is_self_process(pid, effective_exe);
        if is_self || classify_outbound_risk(effective_exe) == OutboundRiskClass::ProtectedOs {
            self.outbound_classifier.mark_protected_os(pid);
        } else {
            self.outbound_classifier.remove_pid(pid);
        }
        if effective_exe.trim().is_empty() {
            return;
        }
        if self.config.outbound_firewall_enabled && !is_self {
            self.maybe_apply_preemptive_wfp_block_with_motw(effective_exe, has_motw);
        }
        if let Some(inst_id) = instance_id {
            let mut table = self
                .process_table
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            table.mark_launch_guards_applied(inst_id);
        }
    }

    fn finalize_canary_backfill(
        &self,
        pid: u32,
        proc_ctx: &mut ResolvedProcessContext,
        prepared: PreparedCanaryBackfill,
    ) {
        let PreparedCanaryBackfill {
            ident,
            create_time_100ns,
            existing_ppid,
            exe_path,
            command_line,
            res,
        } = prepared;

        if res.exited_at_ms.is_none() && !res.skip_launch_guards {
            self.apply_process_launch_guards(
                ident.pid,
                Some(&res.instance_id),
                &exe_path,
                proc_ctx.origin_url.is_some(),
            );
        }

        let synthetic_start = SensorEvent::ProcessStart {
            identity: ident,
            parent_pid: existing_ppid,
            exe_path: exe_path.clone(),
            command_line: command_line.clone(),
            user_sid: None,
        };
        if let Err(err) = self.store.ingest_event_with_process_metadata(
            &synthetic_start,
            res.parent_instance_id.as_deref(),
            res.exited_at_ms,
            res.superseded_exit
                .as_ref()
                .map(|(id, exit_ms)| (id.as_str(), *exit_ms)),
            proc_ctx.origin_url.as_deref(),
            proc_ctx.proc_sha256.as_deref(),
            false,
            "OBSERVED",
        ) {
            tracing::warn!(
                pid,
                error = %err,
                "failed to persist on-demand backfilled ProcessStart into SQLite store"
            );
        }

        proc_ctx.proc_identity = Some(ident);
        proc_ctx.proc_instance_id = Some(res.instance_id.clone());
        proc_ctx.proc_exe_path = (!exe_path.is_empty()).then_some(exe_path.clone());
        proc_ctx.proc_command_line = (!command_line.is_empty()).then_some(command_line);
        proc_ctx.store_hint = Some(res.instance_id);
        if proc_ctx.parent_exe_path.is_none() {
            proc_ctx.parent_exe_path = res.parent_exe_path;
        }
        if proc_ctx.parent_command_line.is_none() {
            proc_ctx.parent_command_line = res.parent_command_line;
        }

        tracing::debug!(
            pid,
            create_time_100ns,
            exe_path = %exe_path,
            "backfilled missing process context on canary file access via on-demand PID lookup"
        );
    }

    fn handle_canary_file_access(
        &self,
        event: &SensorEvent,
        proc_ctx: &ResolvedProcessContext,
        event_ts_ms: i64,
    ) {
        let SensorEvent::CanaryFileAccess {
            pid,
            target_path,
            category,
            access_mask,
            is_write_or_delete,
            ..
        } = event
        else {
            return;
        };

        // ANALYSIS_0002: dedup check BEFORE the expensive binary inspection so every
        // repeat event in a canary burst does not re-read the executable on the
        // high-priority lane. This is a read-only check; the dedup mark is only set
        // below once the event is confirmed non-allowed (single worker, no race).
        let dedup_key = format!(
            "CANARY:{}:{}",
            category.as_str(),
            target_path.trim().replace('/', "\\").to_ascii_lowercase()
        );
        let already_emitted = proc_ctx
            .proc_instance_id
            .as_deref()
            .is_some_and(|inst_id| self.has_rule_alert_emitted(inst_id, &dedup_key));
        if already_emitted {
            if let Err(err) = self.store.ingest_event_with_exit(
                event,
                proc_ctx.store_hint.as_deref(),
                None,
                false,
                "DEDUP_SUPPRESSED",
            ) {
                tracing::warn!(error = %err, "failed to ingest deduplicated canary event");
            }
            return;
        }

        let exe_path = proc_ctx.proc_exe_path.clone().unwrap_or_default();
        let bin_identity = if exe_path.trim().is_empty() {
            BinaryIdentity {
                exe_path: String::new(),
                sha256: None,
                authenticode: None,
            }
        } else {
            self.inspector.inspect(&exe_path)
        };

        let rules = self.store.list_rules(Some(RuleScope::FileCanaryAllow)).unwrap_or_default();
        let allowed = !exe_path.trim().is_empty()
            && is_allowed_by_rules(
                &bin_identity,
                Some(target_path),
                RuleScope::FileCanaryAllow,
                &rules,
            );

        if allowed {
            if let Err(err) = self.store.ingest_event_with_exit(
                event,
                proc_ctx.store_hint.as_deref(),
                None,
                false,
                "ALLOWED",
            ) {
                tracing::warn!(error = %err, "failed to ingest allowed canary event");
            }
            return;
        }

        // First non-allowed event for this (process, category, target): mark the dedup
        // slot now. Allowed events never consume it, and `record_alert` failure clears
        // it again below (BUG_0004 compensation path).
        if let Some(inst_id) = proc_ctx.proc_instance_id.as_deref() {
            let _ = self.is_new_rule_alert(inst_id, &dedup_key);
        }

        let include_children = matches!(category, CanaryCategory::Honeypot);
        let verified_ident = proc_ctx
            .proc_identity
            .filter(|id| id.create_time_100ns != 0);

        let mut process_suspended = false;
        if is_never_suspend_process(&exe_path) {
            tracing::info!(
                pid = *pid,
                exe_path = %exe_path,
                target_path = %target_path,
                "never-suspend guard skipped suspension on canary alert"
            );
        } else if let Some(ident) = verified_ident {
            match self.defense.suspend_process(&ident, include_children) {
                Ok(()) => process_suspended = true,
                Err(err) => {
                    tracing::warn!(
                        pid = *pid,
                        exe_path = %exe_path,
                        include_children,
                        error = %err,
                        "suspend_process failed on canary access"
                    );
                }
            }
        } else {
            tracing::warn!(
                pid = *pid,
                exe_path = %exe_path,
                target_path = %target_path,
                "skipping process suspension on canary alert: missing non-zero ProcessIdentity create_time_100ns (BUG_0001)"
            );
        }

        // Record only children the actuator actually suspends: `suspend_process` skips
        // descendants it cannot freeze, so confirming each one keeps a never-frozen child
        // out of the resume list and prevents its resume failure from blocking resolution
        // (BUG_0002). The call is idempotent for already-suspended children.
        let suspended_child_idents = if include_children && process_suspended {
            verified_ident
                .as_ref()
                .map(|ident| {
                    self.collect_descendant_identities_for_pid(ident)
                        .into_iter()
                        .filter(|child| {
                            let confirmed = self.defense.suspend_process(child, false).is_ok();
                            if !confirmed {
                                tracing::debug!(
                                    child_pid = child.pid,
                                    "descendant not suspended by actuator; excluding from alert resume list"
                                );
                            }
                            confirmed
                        })
                        .collect()
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let suspended_children: Vec<String> = suspended_child_idents
            .iter()
            .map(ProcessIdentity::instance_id)
            .collect();

        let mut context_obj = serde_json::json!({
            "target_path": target_path,
            "category": category.as_str(),
            "access_mask": access_mask,
            "is_write_or_delete": is_write_or_delete,
            "pid": pid,
            "exe_path": exe_path,
            "command_line": proc_ctx.proc_command_line,
            "parent_exe_path": proc_ctx.parent_exe_path,
            "parent_command_line": proc_ctx.parent_command_line,
            "sha256": bin_identity.sha256,
            "signer_subject": bin_identity.authenticode.as_ref().map(|a| a.signer_subject.as_str()),
            "root_thumbprint": bin_identity.authenticode.as_ref().map(|a| a.root_thumbprint.as_str()),
            "include_children": include_children,
            "origin_url": proc_ctx.origin_url,
            "motw_source": proc_ctx.motw_source,
            "motw_referrer": proc_ctx.motw_referrer,
            "motw_frame_url": proc_ctx.motw_frame_url,
            "motw_zone_id": proc_ctx.motw_zone_id,
        });
        if include_children && process_suspended {
            if let Some(map) = context_obj.as_object_mut() {
                map.insert(
                    "suspended_children".to_string(),
                    serde_json::json!(suspended_children),
                );
            }
        }
        let context_json = context_obj.to_string();

        let alert = AlertRecord {
            alert_id: Uuid::new_v4().to_string(),
            timestamp_ms: event_ts_ms,
            severity: canary_severity(*category),
            source_layer: "LAYER_1_CANARY".to_string(),
            rule_id: format!("LEDR-CANARY-{}", category.as_str().to_ascii_uppercase()),
            title: canary_alert_title(*category, target_path),
            process_instance_id: proc_ctx.proc_instance_id.clone(),
            process_suspended,
            status: AlertStatus::Pending,
            context_json,
            resolved_at_ms: None,
        };

        let record_result = if self.fail_record_alert_for_test.load(Ordering::Acquire) {
            Err(StoreError::InvalidValue {
                field: "alerts.test_injection",
                value: "injected record_alert failure".to_string(),
            })
        } else {
            self.store.record_alert(&alert)
        };

        if let Err(err) = record_result {
            tracing::warn!(
                error = %err,
                alert_id = %alert.alert_id,
                "failed to record canary alert; compensating suspension and dedup state (BUG_0004)"
            );
            if process_suspended {
                if let Some(ident) = verified_ident {
                    if let Err(resume_err) = self.defense.resume_process(&ident) {
                        tracing::warn!(
                            pid = ident.pid,
                            error = %resume_err,
                            "compensation resume_process failed for parent after record_alert error"
                        );
                    }
                    for child in &suspended_child_idents {
                        if let Err(resume_err) = self.defense.resume_process(child) {
                            tracing::debug!(
                                child_pid = child.pid,
                                error = %resume_err,
                                "compensation resume_process skipped for child after record_alert error"
                            );
                        }
                    }
                }
                process_suspended = false;
            }
            if let Some(ref inst_id) = proc_ctx.proc_instance_id {
                self.clear_rule_alert(inst_id, &dedup_key);
            }
            let action = if process_suspended {
                "SUSPENDED"
            } else {
                "ALERTED"
            };
            if let Err(ingest_err) = self.store.ingest_event_with_exit(
                event,
                proc_ctx.store_hint.as_deref(),
                None,
                false,
                action,
            ) {
                tracing::warn!(error = %ingest_err, "failed to ingest canary event after alert error");
            }
            return;
        }

        self.alerts_emitted.fetch_add(1, Ordering::Relaxed);

        let action = if process_suspended {
            "SUSPENDED"
        } else {
            "ALERTED"
        };
        if let Err(err) = self.store.ingest_event_with_exit(
            event,
            proc_ctx.store_hint.as_deref(),
            None,
            false,
            action,
        ) {
            tracing::warn!(error = %err, "failed to ingest canary event");
        }

        if let Err(err) = self.notifier.notify_alert(&alert) {
            tracing::warn!(
                alert_id = %alert.alert_id,
                error = %err,
                "failed to dispatch toast notification for canary alert"
            );
        }
    }

    pub(super) fn has_rule_alert_emitted(&self, instance_id: &str, rule_id: &str) -> bool {
        let table = self
            .process_table
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        table.has_rule_alert_emitted(instance_id, rule_id)
    }

    pub(super) fn is_new_rule_alert(&self, instance_id: &str, rule_id: &str) -> bool {
        let mut table = self
            .process_table
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        table.mark_rule_alert_emitted(instance_id, rule_id)
    }

    pub(super) fn clear_rule_alert(&self, instance_id: &str, rule_id: &str) -> bool {
        let mut table = self
            .process_table
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        table.clear_rule_alert_emitted(instance_id, rule_id)
    }

    pub(super) fn resolve_process_context(
        &self,
        event: &SensorEvent,
        event_ts_ms: i64,
    ) -> ResolvedProcessContext {
        let mut evicted_instance_ids: Vec<String> = Vec::new();
        let ctx = {
            let mut table = self
                .process_table
                .lock()
                .unwrap_or_else(|e| e.into_inner());

            match event {
                SensorEvent::ProcessStart {
                    identity,
                    parent_pid,
                    exe_path,
                    command_line,
                    user_sid,
                } => {
                    let res = table.on_process_start(
                        *identity,
                        *parent_pid,
                        exe_path.clone(),
                        command_line.clone(),
                        user_sid.clone(),
                        event_ts_ms,
                    );
                    evicted_instance_ids = res.evicted_instance_ids;
                let (
                    resolved_exe,
                    resolved_cmd,
                    effective_process_start,
                    origin_url,
                    motw_source,
                    motw_referrer,
                    motw_frame_url,
                    motw_zone_id,
                ) = if let Some(entry) = table.get_by_instance_id(&res.instance_id) {
                    let differs = entry.identity != *identity
                        || entry.ppid != *parent_pid
                        || entry.exe_path != *exe_path
                        || entry.command_line != *command_line
                        || entry.user_sid != *user_sid;
                    let merged_ev = differs.then(|| SensorEvent::ProcessStart {
                        identity: entry.identity,
                        parent_pid: entry.ppid,
                        exe_path: entry.exe_path.clone(),
                        command_line: entry.command_line.clone(),
                        user_sid: entry.user_sid.clone(),
                    });
                    (
                        entry.exe_path.clone(),
                        entry.command_line.clone(),
                        merged_ev,
                        entry.origin_url.clone(),
                        entry.motw_source.clone(),
                        entry.motw_referrer.clone(),
                        entry.motw_frame_url.clone(),
                        entry.motw_zone_id,
                    )
                } else {
                    (
                        exe_path.clone(),
                        command_line.clone(),
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                    )
                };
                ResolvedProcessContext {
                    proc_identity: Some(res.resolved_identity),
                    proc_instance_id: Some(res.instance_id),
                    proc_exe_path: Some(resolved_exe),
                    proc_command_line: (!resolved_cmd.is_empty()).then_some(resolved_cmd),
                    store_hint: res.parent_instance_id,
                    parent_exe_path: res.parent_exe_path,
                    parent_command_line: res.parent_command_line,
                    should_evaluate_sigma: res.should_evaluate_sigma,
                    exited_at_ms: res.exited_at_ms,
                    superseded_exit: res.superseded_exit,
                    skip_store_ingest: res.skip_store_ingest,
                    skip_launch_guards: res.skip_launch_guards,
                    effective_process_start,
                    origin_url,
                    motw_source,
                    motw_referrer,
                    motw_frame_url,
                    motw_zone_id,
                    proc_sha256: None,
                }
            }
            SensorEvent::ProcessStop { pid, .. } => {
                let id = table.on_process_stop(*pid, event_ts_ms);
                let exe_path = id
                    .as_deref()
                    .and_then(|inst_id| table.get_by_instance_id(inst_id))
                    .map(|entry| entry.exe_path.clone());
                ResolvedProcessContext {
                    proc_identity: None,
                    proc_instance_id: id.clone(),
                    proc_exe_path: exe_path,
                    proc_command_line: None,
                    store_hint: id,
                    parent_exe_path: None,
                    parent_command_line: None,
                    should_evaluate_sigma: true,
                    exited_at_ms: None,
                    superseded_exit: None,
                    skip_store_ingest: false,
                    skip_launch_guards: false,
                    effective_process_start: None,
                    origin_url: None,
                    motw_source: None,
                    motw_referrer: None,
                    motw_frame_url: None,
                    motw_zone_id: None,
                    proc_sha256: None,
                }
            }
            SensorEvent::DnsQuery { pid, .. }
            | SensorEvent::NetworkConnect { pid, .. }
            | SensorEvent::CanaryFileAccess { pid, .. }
            | SensorEvent::ScriptEvaluated { pid, .. } => {
                // Clone only the fields the context needs: cloning the whole entry would copy
                // `emitted_rule_ids`, which grows with every distinct fired (rule, script) pair.
                let Some((
                    identity,
                    instance_id,
                    exe_path,
                    command_line,
                    parent_instance_id,
                    origin_url,
                    motw_source,
                    motw_referrer,
                    motw_frame_url,
                    motw_zone_id,
                )) = table.lookup_by_pid_at(*pid, event_ts_ms).map(|e| {
                    (
                        e.identity,
                        e.instance_id.clone(),
                        e.exe_path.clone(),
                        e.command_line.clone(),
                        e.parent_instance_id.clone(),
                        e.origin_url.clone(),
                        e.motw_source.clone(),
                        e.motw_referrer.clone(),
                        e.motw_frame_url.clone(),
                        e.motw_zone_id,
                    )
                })
                else {
                    return ResolvedProcessContext::default();
                };
                let (parent_exe, parent_cmd) = parent_instance_id
                    .as_deref()
                    .map(|parent_id| {
                        let (_, p_exe, p_cmd) = table.parent_metadata_by_id(parent_id);
                        (p_exe, p_cmd)
                    })
                    .unwrap_or((None, None));
                ResolvedProcessContext {
                    proc_identity: Some(identity),
                    proc_instance_id: Some(instance_id.clone()),
                    proc_exe_path: Some(exe_path),
                    proc_command_line: (!command_line.is_empty()).then_some(command_line),
                    store_hint: Some(instance_id),
                    parent_exe_path: parent_exe,
                    parent_command_line: parent_cmd,
                    should_evaluate_sigma: true,
                    exited_at_ms: None,
                    superseded_exit: None,
                    skip_store_ingest: false,
                    skip_launch_guards: false,
                    effective_process_start: None,
                    origin_url,
                    motw_source,
                    motw_referrer,
                    motw_frame_url,
                    motw_zone_id,
                    proc_sha256: None,
                }
            }
        }
        };
        if ctx.superseded_exit.is_some() || !evicted_instance_ids.is_empty() {
            let mut cache = self
                .verified_app_wide_allows
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some((ref prev_id, _)) = ctx.superseded_exit {
                cache.remove(prev_id);
            }
            for evicted_id in &evicted_instance_ids {
                cache.remove(evicted_id);
            }
        }
        ctx
    }
}

pub(super) struct ResolvedProcessContext {
    pub(super) proc_identity: Option<ProcessIdentity>,
    pub(super) proc_instance_id: Option<String>,
    pub(super) proc_exe_path: Option<String>,
    pub(super) proc_command_line: Option<String>,
    pub(super) store_hint: Option<String>,
    pub(super) parent_exe_path: Option<String>,
    pub(super) parent_command_line: Option<String>,
    pub(super) should_evaluate_sigma: bool,
    /// Inferred exit time carried from [`ProcessStartResolution`] for older snapshot
    /// incarnations so the store row does not stay "running" forever.
    pub(super) exited_at_ms: Option<i64>,
    /// Previous `(process_instance_id, exit_ms)` superseded in memory by this `ProcessStart`
    /// so the store closes the replaced row atomically in the same transaction.
    pub(super) superseded_exit: Option<(String, i64)>,
    /// `true` when an unverified `create_time_100ns == 0` snapshot was absorbed into an active
    /// verified process without adding any new metadata and must not write a `pid:0` row.
    pub(super) skip_store_ingest: bool,
    /// `true` when a re-enrichment `ProcessStart` must not re-run MOTW or preemptive WFP guards.
    pub(super) skip_launch_guards: bool,
    /// Merged `ProcessStart` carrying the table's consolidated identity and non-clobbering
    /// metadata whenever the normalized in-memory entry differs from the incoming `ProcessStart`
    /// event, so `EarlyPruner`, `SigmaEngine`, alert context, and SQLite ingestion evaluate the
    /// same launch metadata.
    pub(super) effective_process_start: Option<SensorEvent>,
    pub(super) origin_url: Option<String>,
    pub(super) motw_source: Option<String>,
    pub(super) motw_referrer: Option<String>,
    pub(super) motw_frame_url: Option<String>,
    pub(super) motw_zone_id: Option<u32>,
    pub(super) proc_sha256: Option<String>,
}

impl Default for ResolvedProcessContext {
    fn default() -> Self {
        Self {
            proc_identity: None,
            proc_instance_id: None,
            proc_exe_path: None,
            proc_command_line: None,
            store_hint: None,
            parent_exe_path: None,
            parent_command_line: None,
            should_evaluate_sigma: true,
            exited_at_ms: None,
            superseded_exit: None,
            skip_store_ingest: false,
            skip_launch_guards: false,
            effective_process_start: None,
            origin_url: None,
            motw_source: None,
            motw_referrer: None,
            motw_frame_url: None,
            motw_zone_id: None,
            proc_sha256: None,
        }
    }
}

const fn canary_severity(category: CanaryCategory) -> AlertSeverity {
    match category {
        CanaryCategory::Honeypot => AlertSeverity::Critical,
        CanaryCategory::CookieDb
        | CanaryCategory::LoginData
        | CanaryCategory::SshKey
        | CanaryCategory::CloudCredential
        | CanaryCategory::EnvFile
        | CanaryCategory::AutorunRegistry => AlertSeverity::High,
    }
}

fn canary_alert_title(category: CanaryCategory, target_path: &str) -> String {
    let label = match category {
        CanaryCategory::CookieDb => "Browser Cookie Store Access",
        CanaryCategory::LoginData => "Browser Credential Store Access",
        CanaryCategory::SshKey => "SSH Private Key Access",
        CanaryCategory::CloudCredential => "Cloud Credential Access",
        CanaryCategory::EnvFile => "Project .env Secret Access",
        CanaryCategory::Honeypot => "Honeypot Decoy Modification",
        CanaryCategory::AutorunRegistry => "Autorun Persistence Modification",
    };
    let name = target_path
        .rsplit(['\\', '/'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(target_path);
    format!("{label}: {name}")
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use ledr_proto::{ActiveDefenseController, AlertRecord, ProcessIdentity, SensorEvent};
    use ledr_rules::{BinaryIdentity, EarlyPruner, SigmaEngine};
    use ledr_store::LedrStore;

    use super::super::motw::{LateMotwAttribution, MotwAttribution, MotwMatchStage};
    use super::super::{
        BinaryInspector, DaemonConfig, DaemonEngine, NotificationDispatcher,
        OutboundEnforcementMode,
    };
    use super::WfpRuleManager;

    struct RecordingWfpDefense {
        next_handle: AtomicU64,
        added_wfp: Mutex<Vec<String>>,
    }

    impl RecordingWfpDefense {
        fn new() -> Self {
            Self {
                next_handle: AtomicU64::new(1),
                added_wfp: Mutex::new(Vec::new()),
            }
        }

        fn added_wfp(&self) -> Vec<String> {
            self.added_wfp
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
    }

    impl ActiveDefenseController for RecordingWfpDefense {
        fn suspend_process(&self, _: &ProcessIdentity, _: bool) -> Result<(), String> {
            Ok(())
        }
        fn resume_process(&self, _: &ProcessIdentity) -> Result<(), String> {
            Ok(())
        }
        fn terminate_process(&self, _: &ProcessIdentity, _: bool) -> Result<(), String> {
            Ok(())
        }
        fn add_wfp_app_rule(&self, exe: &Path, _: Option<IpAddr>, _: bool) -> Result<u64, String> {
            self.added_wfp
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(exe.display().to_string());
            Ok(self.next_handle.fetch_add(1, Ordering::Relaxed))
        }
        fn remove_wfp_rule(&self, _: u64) -> Result<(), String> {
            Ok(())
        }
    }

    struct NoopNotifier;
    impl NotificationDispatcher for NoopNotifier {
        fn notify_alert(&self, _: &AlertRecord) -> Result<(), String> {
            Ok(())
        }
    }

    struct EmptyInspector;
    impl BinaryInspector for EmptyInspector {
        fn inspect(&self, exe_path: &str) -> BinaryIdentity {
            BinaryIdentity {
                exe_path: exe_path.to_string(),
                sha256: None,
                authenticode: None,
            }
        }
    }

    /// `MOTW-LATE-01`: `apply_late_motw_attribution` must separate SQLite `COALESCE` backfill
    /// from active-only WFP/outbound-classifier updates across active, exited, pre-populated,
    /// `process_table`-evicted (full and partial `origin_url`-only), and PID-reused successor
    /// instances without polluting live successor processes on reused PIDs.
    #[tokio::test]
    async fn motw_late_01_separates_sqlite_backfill_from_active_defense_across_active_exited_and_evicted(
    ) {
        let store = LedrStore::open_in_memory().expect("open store");
        let defense = Arc::new(RecordingWfpDefense::new());
        let engine = DaemonEngine::start_with_dependencies(
            store.clone(),
            SigmaEngine::default(),
            EarlyPruner::default(),
            DaemonConfig {
                outbound_firewall_enabled: true,
                outbound_enforcement_mode: OutboundEnforcementMode::Enforce,
                motw_sync_wait_budget_ms: 0,
                ..DaemonConfig::default()
            },
            defense.clone(),
            Arc::new(NoopNotifier),
            Arc::new(EmptyInspector),
        );
        engine.shutdown_and_flush().await.expect("stop pipeline");

        let base_ft = 134_000_000_000_000_000u64;
        let base_ms = 1_760_025_000_000i64;
        let prior_url = "https://prior.example.invalid/orig.exe";
        let prior_sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let late_url = "https://late.example.invalid/new.exe";
        let late_sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        let active_unset_id = ProcessIdentity::new(61_001, base_ft + 1);
        let active_preset_id = ProcessIdentity::new(61_002, base_ft + 2);
        let exited_unset_id = ProcessIdentity::new(61_003, base_ft + 3);
        let exited_preset_id = ProcessIdentity::new(61_004, base_ft + 4);
        let evicted_unset_id = ProcessIdentity::new(61_005, base_ft + 5);
        let evicted_preset_id = ProcessIdentity::new(61_006, base_ft + 6);
        let evicted_partial_id = ProcessIdentity::new(61_007, base_ft + 7);
        let reused_exited_successor_id = ProcessIdentity::new(61_003, base_ft + 100);
        let reused_evicted_successor_id = ProcessIdentity::new(61_005, base_ft + 105);

        let specs = [
            (
                active_unset_id,
                r"C:\Late01\active_unset.exe",
                true,
                false,
                None,
                None,
            ),
            (
                active_preset_id,
                r"C:\Late01\active_preset.exe",
                true,
                false,
                Some(prior_url),
                None,
            ),
            (
                exited_unset_id,
                r"C:\Late01\exited_unset.exe",
                true,
                true,
                None,
                None,
            ),
            (
                exited_preset_id,
                r"C:\Late01\exited_preset.exe",
                true,
                true,
                Some(prior_url),
                None,
            ),
            (
                evicted_unset_id,
                r"C:\Late01\evicted_unset.exe",
                false,
                true,
                None,
                None,
            ),
            (
                evicted_preset_id,
                r"C:\Late01\evicted_preset.exe",
                false,
                true,
                Some(prior_url),
                Some(prior_sha),
            ),
            (
                evicted_partial_id,
                r"C:\Late01\evicted_partial.exe",
                false,
                true,
                Some(prior_url),
                None,
            ),
        ];

        for (ident, exe, in_table, exited, init_url, init_sha) in specs {
            let start_ev = SensorEvent::ProcessStart {
                identity: ident,
                parent_pid: 4,
                exe_path: exe.to_string(),
                command_line: exe.to_string(),
                user_sid: None,
            };
            store
                .ingest_event_with_process_metadata(
                    &start_ev,
                    None,
                    exited.then_some(base_ms + 50),
                    None,
                    init_url,
                    init_sha,
                    false,
                    "OBSERVED",
                )
                .expect("ingest process row");
            if in_table {
                let mut table = engine
                    .process_table
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let res = table.on_process_start(
                    ident,
                    4,
                    exe.to_string(),
                    exe.to_string(),
                    None,
                    base_ms,
                );
                if let Some(url) = init_url {
                    assert!(table.set_motw_metadata(
                        &res.instance_id,
                        url.to_string(),
                        "zone_identifier_ads".to_string(),
                        None,
                        None,
                        Some(3),
                    ));
                }
                if exited {
                    assert_eq!(
                        table.on_process_stop(ident.pid, base_ms + 50),
                        Some(res.instance_id)
                    );
                }
            }
        }

        // Register active successor processes that reuse PIDs 61_003 (after `exited_unset_id`
        // stopped) and 61_005 (after `evicted_unset_id` was evicted) with distinct creation times.
        let successor_specs = [
            (
                reused_exited_successor_id,
                r"C:\Late01\reused_exited_successor.exe",
                base_ms + 100,
            ),
            (
                reused_evicted_successor_id,
                r"C:\Late01\reused_evicted_successor.exe",
                base_ms + 105,
            ),
        ];
        for (ident, exe, started_ms) in successor_specs {
            let start_ev = SensorEvent::ProcessStart {
                identity: ident,
                parent_pid: 4,
                exe_path: exe.to_string(),
                command_line: exe.to_string(),
                user_sid: None,
            };
            store
                .ingest_event_with_process_metadata(
                    &start_ev,
                    None,
                    None,
                    None,
                    None,
                    None,
                    false,
                    "OBSERVED",
                )
                .expect("ingest successor process row");
            let mut table = engine
                .process_table
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let res = table.on_process_start(
                ident,
                4,
                exe.to_string(),
                exe.to_string(),
                None,
                started_ms,
            );
            assert_eq!(res.instance_id, ident.instance_id());
            assert!(!res.skip_store_ingest);
        }
        {
            let table = engine
                .process_table
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            assert_eq!(
                table.lookup_by_pid(61_003).map(|e| e.instance_id.as_str()),
                Some(reused_exited_successor_id.instance_id().as_str()),
                "PID 61_003 must now point to the active reused successor process"
            );
            assert_eq!(
                table.lookup_by_pid(61_005).map(|e| e.instance_id.as_str()),
                Some(reused_evicted_successor_id.instance_id().as_str()),
                "PID 61_005 must now point to the active reused successor process"
            );
        }
        store.flush_batch().expect("flush initial rows");

        // Mark PIDs steady in `outbound_classifier`: active_unset must be cleared, while
        // active_preset and PID-reused active successor processes (61_003, 61_005) must remain steady.
        for pid in [61_001, 61_002, 61_003, 61_005] {
            engine.outbound_classifier.mark_steady(pid);
        }

        engine.apply_late_motw_attribution(LateMotwAttribution {
            instance_ids: vec![
                active_unset_id.instance_id(),
                active_preset_id.instance_id(),
                exited_unset_id.instance_id(),
                exited_preset_id.instance_id(),
                evicted_unset_id.instance_id(),
                evicted_preset_id.instance_id(),
                evicted_partial_id.instance_id(),
            ],
            attribution: MotwAttribution {
                origin_url: late_url.to_string(),
                referrer_url: None,
                frame_url: None,
                sha256: Some(late_sha.to_string()),
                zone_id: Some(3),
                stage: MotwMatchStage::DownloadSha256,
            },
        });

        let query_row = |ident: ProcessIdentity| {
            let snap = store
                .query_flight_recorder(10, Some(&ident.instance_id()))
                .expect("query process row");
            assert_eq!(snap.processes.len(), 1);
            snap.processes.into_iter().next().unwrap()
        };

        // 1. Active without prior URL -> table + SQLite updated, classifier cleared, WFP added.
        let r_active_unset = query_row(active_unset_id);
        assert_eq!(r_active_unset.origin_url.as_deref(), Some(late_url));
        assert_eq!(r_active_unset.sha256.as_deref(), Some(late_sha));
        assert!(!engine.outbound_classifier.is_steady_pid(61_001));

        // 2. Active with prior URL -> skipped (non-overwrite, classifier/WFP untouched).
        let r_active_preset = query_row(active_preset_id);
        assert_eq!(r_active_preset.origin_url.as_deref(), Some(prior_url));
        assert_eq!(r_active_preset.sha256, None);
        assert!(engine.outbound_classifier.is_steady_pid(61_002));

        // 3. Exited without prior URL -> SQLite backfilled, table unchanged, active PID-reused
        //    successor untouched (SQLite, process_table, has_active_motw_for_exe_key, classifier, WFP).
        let r_exited_unset = query_row(exited_unset_id);
        assert_eq!(r_exited_unset.origin_url.as_deref(), Some(late_url));
        assert_eq!(r_exited_unset.sha256.as_deref(), Some(late_sha));
        assert!(r_exited_unset.exited_at_ms.is_some());
        assert!(engine.outbound_classifier.is_steady_pid(61_003));
        let r_reused_exited_succ = query_row(reused_exited_successor_id);
        assert_eq!(r_reused_exited_succ.origin_url, None);
        assert_eq!(r_reused_exited_succ.sha256, None);
        assert!(r_reused_exited_succ.exited_at_ms.is_none());
        {
            let table = engine
                .process_table
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            assert_eq!(
                table
                    .get_by_instance_id(&active_unset_id.instance_id())
                    .and_then(|e| e.origin_url.as_deref()),
                Some(late_url)
            );
            assert_eq!(
                table
                    .get_by_instance_id(&exited_unset_id.instance_id())
                    .and_then(|e| e.origin_url.as_deref()),
                None,
                "exited process_table entry must remain immutable in memory"
            );
            let exited_succ = table
                .get_by_instance_id(&reused_exited_successor_id.instance_id())
                .expect("reused_exited_successor must remain active in process_table");
            assert_eq!(exited_succ.origin_url, None);
            assert_eq!(exited_succ.motw_source, None);
            assert!(exited_succ.exited_at_ms.is_none());
            assert!(!table.has_active_motw_for_exe_key(&WfpRuleManager::exe_key(
                r"C:\Late01\reused_exited_successor.exe"
            )));
            assert!(table
                .get_by_instance_id(&evicted_unset_id.instance_id())
                .is_none());
            assert!(table
                .get_by_instance_id(&evicted_partial_id.instance_id())
                .is_none());
            let evicted_succ = table
                .get_by_instance_id(&reused_evicted_successor_id.instance_id())
                .expect("reused_evicted_successor must remain active in process_table");
            assert_eq!(evicted_succ.origin_url, None);
            assert_eq!(evicted_succ.motw_source, None);
            assert!(evicted_succ.exited_at_ms.is_none());
            assert!(!table.has_active_motw_for_exe_key(&WfpRuleManager::exe_key(
                r"C:\Late01\reused_evicted_successor.exe"
            )));
        }

        // 4. Exited with prior URL -> skipped.
        let r_exited_preset = query_row(exited_preset_id);
        assert_eq!(r_exited_preset.origin_url.as_deref(), Some(prior_url));
        assert_eq!(r_exited_preset.sha256, None);

        // 5. Evicted from process_table without prior URL -> SQLite backfilled, active PID-reused
        //    successor untouched (SQLite, process_table, classifier, WFP).
        let r_evicted_unset = query_row(evicted_unset_id);
        assert_eq!(r_evicted_unset.origin_url.as_deref(), Some(late_url));
        assert_eq!(r_evicted_unset.sha256.as_deref(), Some(late_sha));
        assert!(r_evicted_unset.exited_at_ms.is_some());
        assert!(engine.outbound_classifier.is_steady_pid(61_005));
        let r_reused_evicted_succ = query_row(reused_evicted_successor_id);
        assert_eq!(r_reused_evicted_succ.origin_url, None);
        assert_eq!(r_reused_evicted_succ.sha256, None);
        assert!(r_reused_evicted_succ.exited_at_ms.is_none());

        // 6. Evicted from process_table with prior URL/SHA -> COALESCE preserves both.
        let r_evicted_preset = query_row(evicted_preset_id);
        assert_eq!(r_evicted_preset.origin_url.as_deref(), Some(prior_url));
        assert_eq!(r_evicted_preset.sha256.as_deref(), Some(prior_sha));

        // 7. Evicted from process_table with prior URL but missing SHA -> COALESCE preserves
        //    existing URL while backfilling missing SHA-256 only.
        let r_evicted_partial = query_row(evicted_partial_id);
        assert_eq!(r_evicted_partial.origin_url.as_deref(), Some(prior_url));
        assert_eq!(r_evicted_partial.sha256.as_deref(), Some(late_sha));
        assert!(r_evicted_partial.exited_at_ms.is_some());

        // Only `active_unset.exe` must receive an L-18 pre-emptive WFP block.
        let wfp = defense.added_wfp();
        assert_eq!(wfp.len(), 1, "unexpected WFP calls: {wfp:?}");
        assert!(wfp[0].ends_with("active_unset.exe"));
    }

    #[test]
    fn self_check_path_normalization_handles_nt_unc_mixed_slashes_and_unicode() {
        use super::super::normalize_exe_path_for_self_check;

        let expected_local = r"c:\program files\localedr\ledr-daemon.exe";
        for variant in [
            r"C:\Program Files\LocalEDR\ledr-daemon.exe",
            r"\\?\C:\Program Files\LocalEDR\ledr-daemon.exe",
            r"\??\C:\Program Files\LocalEDR\ledr-daemon.exe",
            r"/??/C:/Program Files/LocalEDR/LEDR-DAEMON.EXE",
            r"\??/C:/Program Files/LocalEDR/ledr-daemon.exe",
            r"//?/C:\Program Files/LocalEDR\ledr-daemon.exe",
            r"  \??\C:\Program Files\LocalEDR\ledr-daemon.exe  ",
        ] {
            assert_eq!(
                normalize_exe_path_for_self_check(variant),
                expected_local,
                "variant `{variant}` failed to normalize to `{expected_local}`"
            );
        }

        let expected_unc = r"\\fileserver\share\ledr-daemon.exe";
        for unc_variant in [
            r"\\FileServer\Share\ledr-daemon.exe",
            r"\\?\UNC\FileServer\Share\ledr-daemon.exe",
            r"\??\UNC\FileServer\Share\ledr-daemon.exe",
            r"//?/UNC/FileServer/Share/LEDR-DAEMON.EXE",
            r"\??\UNC/FileServer/Share/ledr-daemon.exe",
        ] {
            assert_eq!(
                normalize_exe_path_for_self_check(unc_variant),
                expected_unc,
                "UNC variant `{unc_variant}` failed to normalize to `{expected_unc}`"
            );
        }

        assert_eq!(
            normalize_exe_path_for_self_check(r"\??\C:\Users\日本語\ÄÖÜ\LEDR-DAEMON.EXE"),
            r"c:\users\日本語\äöü\ledr-daemon.exe"
        );
        assert_eq!(normalize_exe_path_for_self_check(""), "");
        assert_eq!(normalize_exe_path_for_self_check("   "), "");
        assert_eq!(normalize_exe_path_for_self_check(r"\??\"), "");
        assert_eq!(normalize_exe_path_for_self_check(r"\??\   "), "");
    }

    #[tokio::test]
    async fn self_process_delayed_motw_backfill_preserves_protected_and_skips_wfp() {
        let self_pid = std::process::id();
        let other_pid = if self_pid == u32::MAX {
            self_pid - 1
        } else {
            self_pid + 1
        };
        let raw_self_exe = std::env::current_exe()
            .expect("resolve current_exe")
            .to_string_lossy()
            .into_owned();
        let bare_self_exe = raw_self_exe
            .strip_prefix(r"\\?\")
            .unwrap_or(&raw_self_exe)
            .to_string();

        let store = LedrStore::open_in_memory().expect("open store");
        let defense = Arc::new(RecordingWfpDefense::new());
        let cfg = DaemonConfig {
            outbound_firewall_enabled: true,
            outbound_enforcement_mode: OutboundEnforcementMode::Enforce,
            ..DaemonConfig::default()
        };
        let engine = DaemonEngine::start_with_controllers(
            store.clone(),
            SigmaEngine::from_rules(Vec::new()).expect("empty sigma"),
            EarlyPruner::default(),
            cfg,
            defense.clone(),
            Arc::new(crate::notify::NoopNotificationDispatcher),
        );

        let self_ident = ProcessIdentity::new(self_pid, 10_001);
        let other_ident = ProcessIdentity::new(other_pid, 10_002);

        // Seed self and another PID running the same binary; seed must NOT schedule MOTW for self.
        let self_start = SensorEvent::ProcessStart {
            identity: self_ident,
            parent_pid: 4,
            exe_path: bare_self_exe.clone(),
            command_line: bare_self_exe.clone(),
            user_sid: None,
        };
        let other_start = SensorEvent::ProcessStart {
            identity: other_ident,
            parent_pid: 4,
            exe_path: bare_self_exe.clone(),
            command_line: bare_self_exe.clone(),
            user_sid: None,
        };
        let self_seed = engine.process_seed_process_start(&self_start);
        assert!(
            self_seed.motw_candidate.is_none(),
            "seed_processes must not schedule MOTW inspection for the daemon's own process"
        );
        let other_seed = engine.process_seed_process_start(&other_start);
        assert!(
            other_seed.motw_candidate.is_some(),
            "seed_processes must still schedule MOTW inspection for non-self PIDs"
        );
        store.flush_batch().expect("flush seeded rows");
        assert!(engine.outbound_classifier.is_steady_pid(self_pid));

        // Even if a delayed MOTW backfill arrives for self_ident, it must preserve self_pid's
        // ProtectedOs steady marking and must NOT install a pre-emptive WFP block on self.
        engine.apply_late_motw_attribution(LateMotwAttribution {
            instance_ids: vec![self_ident.instance_id()],
            attribution: MotwAttribution {
                origin_url: "https://evil.example.invalid/ledr-daemon.exe".to_string(),
                stage: MotwMatchStage::ZoneIdentifierAds,
                referrer_url: None,
                frame_url: None,
                zone_id: Some(3),
                sha256: Some("a".repeat(64)),
            },
        });
        assert!(
            engine.outbound_classifier.is_steady_pid(self_pid),
            "delayed MOTW backfill must not clear self_pid ProtectedOs marker"
        );
        assert!(
            defense.added_wfp().is_empty(),
            "delayed MOTW backfill for self_pid must not install WFP block: {:?}",
            defense.added_wfp()
        );

        // By contrast, delayed MOTW backfill for `other_pid` running the same binary MUST clear
        // any steady marking and install an L-18 pre-emptive WFP block.
        engine.outbound_classifier.mark_steady(other_pid);
        engine.apply_late_motw_attribution(LateMotwAttribution {
            instance_ids: vec![other_ident.instance_id()],
            attribution: MotwAttribution {
                origin_url: "https://evil.example.invalid/copy.exe".to_string(),
                stage: MotwMatchStage::ZoneIdentifierAds,
                referrer_url: None,
                frame_url: None,
                zone_id: Some(3),
                sha256: Some("b".repeat(64)),
            },
        });
        assert!(
            !engine.outbound_classifier.is_steady_pid(other_pid),
            "delayed MOTW backfill must clear steady marker for non-self PID"
        );
        assert_eq!(
            defense.added_wfp().len(),
            1,
            "delayed MOTW backfill for non-self PID must install L-18 pre-emptive WFP block"
        );

        engine.shutdown_and_flush().await.expect("shutdown engine");
    }
}
