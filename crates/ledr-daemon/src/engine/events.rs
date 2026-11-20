use std::collections::hash_map::DefaultHasher;
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
#[cfg(doc)]
use crate::process_table::ProcessStartResolution;

use super::{current_unix_ms, event_timestamp_ms, DaemonEngine};

pub(super) struct DnsCorrelationUpdate {
    pub(super) instance_id: String,
    pub(super) exe_key: String,
    pub(super) accepted_ips: Vec<IpAddr>,
}

impl DaemonEngine {
    pub(super) fn process_event(&self, event: &SensorEvent) {
        let _ = self.process_event_with_lane(event, event.default_lane());
    }

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
            // L-06: Read-only honeypot opens are ignored to avoid SearchIndexer/backup false positives.
            self.high_priority_processed.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        let now_ms = current_unix_ms();
        let event_ts_ms = event_timestamp_ms(event, now_ms);

        let proc_ctx = self.resolve_process_context(event, event_ts_ms);

        if matches!(event, SensorEvent::CanaryFileAccess { .. }) {
            let mut proc_ctx = proc_ctx;
            self.backfill_canary_process_context_if_missing(event, &mut proc_ctx, event_ts_ms);
            self.handle_canary_file_access(event, &proc_ctx, event_ts_ms);
            self.high_priority_processed.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        let ctx = EventContext::with_parent(
            event,
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
                    "event": event,
                    "parent_exe_path": proc_ctx.parent_exe_path,
                    "parent_command_line": proc_ctx.parent_command_line,
                    "matched_fields": m.matched_fields,
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
                if proc_ctx.exited_at_ms.is_none() {
                    if classify_outbound_risk(exe_path) == OutboundRiskClass::ProtectedOs {
                        self.outbound_classifier.mark_protected_os(identity.pid);
                    } else {
                        self.outbound_classifier.remove_pid(identity.pid);
                    }
                    if self.config.outbound_firewall_enabled {
                        self.maybe_apply_preemptive_wfp_block(exe_path);
                    }
                }
                "OBSERVED"
            }
            SensorEvent::ProcessStop { pid, .. } => {
                if let Some(ref inst_id) = proc_ctx.proc_instance_id {
                    self.outbound_classifier.remove_pid(*pid);
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
                query_name,
                resolved_ips,
                ..
            } => {
                if !resolved_ips.is_empty() {
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
                    if self.config.outbound_firewall_enabled {
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

        if let Err(err) = self.store.ingest_event_with_exit(
            event,
            proc_ctx.store_hint.as_deref(),
            proc_ctx.exited_at_ms,
            is_nrd,
            action,
        ) {
            tracing::warn!(error = %err, "failed to ingest event into SQLite store");
        } else if flush_now {
            if let Err(err) = self.store.flush_batch() {
                tracing::warn!(error = %err, "failed to flush network alert telemetry batch");
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
    fn backfill_canary_process_context_if_missing(
        &self,
        event: &SensorEvent,
        proc_ctx: &mut ResolvedProcessContext,
        event_ts_ms: i64,
    ) {
        let SensorEvent::CanaryFileAccess { pid, .. } = event else {
            return;
        };
        let needs_create_time = proc_ctx
            .proc_identity
            .is_none_or(|id| id.create_time_100ns == 0);
        let needs_exe_path = proc_ctx
            .proc_exe_path
            .as_deref()
            .is_none_or(|p| p.trim().is_empty());
        if !needs_create_time && !needs_exe_path {
            return;
        }

        let Some(live) = self.live_process_inspector.inspect_live_process(*pid) else {
            return;
        };
        self.apply_canary_live_process_backfill(*pid, proc_ctx, event_ts_ms, live);
    }

    fn apply_canary_live_process_backfill(
        &self,
        pid: u32,
        proc_ctx: &mut ResolvedProcessContext,
        event_ts_ms: i64,
        live: ledr_sensor_win::etw::LiveProcessInfo,
    ) {
        if live.create_time_100ns == 0 {
            return;
        }
        // Guard against PID reuse (`BUG_0001`): if the live OS process at `pid` was created
        // strictly after the canary event timestamp, it cannot be the original accessor.
        let live_created_ms = super::filetime_100ns_to_unix_ms(live.create_time_100ns, i64::MAX);
        if live_created_ms > event_ts_ms {
            tracing::debug!(
                pid,
                live_created_ms,
                event_ts_ms,
                "skipping canary process backfill because live process started after event timestamp (possible PID reuse)"
            );
            return;
        }

        // Guard against PID reuse: if we already have a non-zero creation timestamp for this
        // process context, never overwrite it with a different live process that reused the PID.
        if let Some(existing_id) = proc_ctx.proc_identity {
            if existing_id.create_time_100ns != 0
                && existing_id.create_time_100ns != live.create_time_100ns
            {
                return;
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
            let Some(live_exe) = live_exe_opt else {
                return;
            };
            if !existing_exe
                .replace('/', "\\")
                .eq_ignore_ascii_case(&live_exe.replace('/', "\\"))
            {
                return;
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
            return;
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
        let ident = ProcessIdentity::new(pid, live.create_time_100ns);
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

        let synthetic_start = SensorEvent::ProcessStart {
            identity: ident,
            parent_pid: existing_ppid,
            exe_path: exe_path.clone(),
            command_line: command_line.clone(),
            user_sid: None,
        };
        if let Err(err) = self.store.ingest_event_with_exit(
            &synthetic_start,
            res.parent_instance_id.as_deref(),
            res.exited_at_ms,
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
            create_time_100ns = live.create_time_100ns,
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
                ResolvedProcessContext {
                    proc_identity: Some(*identity),
                    proc_instance_id: Some(res.instance_id),
                    proc_exe_path: Some(exe_path.clone()),
                    proc_command_line: (!command_line.is_empty()).then(|| command_line.clone()),
                    store_hint: res.parent_instance_id,
                    parent_exe_path: res.parent_exe_path,
                    parent_command_line: res.parent_command_line,
                    should_evaluate_sigma: res.should_evaluate_sigma,
                    exited_at_ms: res.exited_at_ms,
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
                }
            }
            SensorEvent::DnsQuery { pid, .. }
            | SensorEvent::NetworkConnect { pid, .. }
            | SensorEvent::CanaryFileAccess { pid, .. }
            | SensorEvent::ScriptEvaluated { pid, .. } => {
                // Clone only the fields the context needs: cloning the whole entry would copy
                // `emitted_rule_ids`, which grows with every distinct fired (rule, script) pair.
                let Some((identity, instance_id, exe_path, command_line, parent_instance_id)) =
                    table.lookup_by_pid_at(*pid, event_ts_ms).map(|e| {
                        (
                            e.identity,
                            e.instance_id.clone(),
                            e.exe_path.clone(),
                            e.command_line.clone(),
                            e.parent_instance_id.clone(),
                        )
                    })
                else {
                    return ResolvedProcessContext::default();
                };
                let (parent_exe, parent_cmd) = parent_instance_id
                    .as_deref()
                    .and_then(|parent_id| table.get_by_instance_id(parent_id))
                    .map(|p| {
                        (
                            Some(p.exe_path.clone()),
                            (!p.command_line.is_empty()).then(|| p.command_line.clone()),
                        )
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
                }
            }
        }
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
