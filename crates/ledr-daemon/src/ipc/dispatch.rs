//! IPC request authorization enforcement and command dispatch to `DaemonEngine`.

use ledr_proto::{
    AlertDecision, AllowPermanentPathMode, IpcRequest, IpcResponse, AUTHORIZED_BRIDGE_EXE_PATH,
    AUTHORIZED_UI_EXE_PATH,
};

use crate::engine::{BrowserEventOutcome, BrowserReportError, DaemonEngine, PolicyRuleError};

use super::auth::verify_authorized_caller_binary_with_inspector;

/// Command-scoped caller authorization policy for Named Pipe IPC requests (`L-25`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CallerAuthPolicy {
    /// Unauthenticated health check (`Ping`).
    Public,
    /// Requires `AUTHORIZED_UI_EXE_PATH`; rejects with `"UNAUTHORIZED"`.
    UiOnly,
    /// Requires `AUTHORIZED_BRIDGE_EXE_PATH`; rejects with `"UNAUTHORIZED_CALLER"`.
    BridgeOnly,
    /// Accepts either `AUTHORIZED_UI_EXE_PATH` or `AUTHORIZED_BRIDGE_EXE_PATH`; rejects with `"UNAUTHORIZED"`.
    UiOrBridge,
}

/// Maps an [`IpcRequest`] variant to its required [`CallerAuthPolicy`].
pub(super) fn caller_auth_policy_for_request(req: &IpcRequest) -> CallerAuthPolicy {
    match req {
        IpcRequest::Ping => CallerAuthPolicy::Public,
        IpcRequest::ResolveAlert { .. }
        | IpcRequest::ResolveAlertWithOptions { .. }
        | IpcRequest::ResolveAlertScoped { .. }
        | IpcRequest::UpsertRule { .. }
        | IpcRequest::DeleteRule { .. }
        | IpcRequest::UpsertScopedRule { .. }
        | IpcRequest::DeleteScopedRule { .. }
        | IpcRequest::GetFlightRecorder { .. }
        | IpcRequest::GetAlerts { .. }
        | IpcRequest::ListRules { .. }
        | IpcRequest::ListScopedRules { .. }
        | IpcRequest::GetPipelineMetrics => CallerAuthPolicy::UiOnly,
        IpcRequest::ReportDownloadOrigin { .. } | IpcRequest::ReportBrowserEvent { .. } => {
            CallerAuthPolicy::BridgeOnly
        }
        IpcRequest::CheckDomainRisk { .. } => CallerAuthPolicy::UiOrBridge,
    }
}

/// Enforces `policy` against `caller_exe` using `verify_authorized_caller_binary_with_inspector`
/// (`inspect_uncached` on Authenticode paths, no in-app or inter-process caching).
pub(super) fn authorize_caller_policy(
    engine: &DaemonEngine,
    caller_exe: Option<&str>,
    policy: CallerAuthPolicy,
) -> Option<IpcResponse> {
    if matches!(policy, CallerAuthPolicy::Public) {
        return None;
    }

    let cfg = engine.config();
    if cfg.dev_mode_bypass_ui_auth {
        return None;
    }

    let inspector = engine.inspector().as_ref();
    let verify_ui = || {
        verify_authorized_caller_binary_with_inspector(
            inspector,
            caller_exe,
            AUTHORIZED_UI_EXE_PATH,
            cfg.authorized_ui_sha256.as_deref(),
            cfg.authorized_ui_signer.as_deref(),
            cfg.authorized_ui_root_thumbprint.as_deref(),
            false,
        )
    };
    let verify_bridge = || {
        verify_authorized_caller_binary_with_inspector(
            inspector,
            caller_exe,
            AUTHORIZED_BRIDGE_EXE_PATH,
            cfg.authorized_bridge_sha256.as_deref(),
            cfg.authorized_bridge_signer.as_deref(),
            cfg.authorized_bridge_root_thumbprint.as_deref(),
            false,
        )
    };

    match policy {
        CallerAuthPolicy::Public => None,
        CallerAuthPolicy::UiOnly => {
            if verify_ui() {
                None
            } else {
                Some(IpcResponse::Error {
                    code: "UNAUTHORIZED".to_string(),
                    message: format!(
                        "caller {:?} is not authorized for UI IPC command (expected {})",
                        caller_exe, AUTHORIZED_UI_EXE_PATH
                    ),
                })
            }
        }
        CallerAuthPolicy::BridgeOnly => {
            if verify_bridge() {
                None
            } else {
                Some(IpcResponse::Error {
                    code: "UNAUTHORIZED_CALLER".to_string(),
                    message: format!(
                        "caller {:?} is not authorized for browser bridge IPC command (expected {})",
                        caller_exe, AUTHORIZED_BRIDGE_EXE_PATH
                    ),
                })
            }
        }
        CallerAuthPolicy::UiOrBridge => {
            if verify_ui() || verify_bridge() {
                None
            } else {
                Some(IpcResponse::Error {
                    code: "UNAUTHORIZED".to_string(),
                    message: format!(
                        "caller {:?} is not authorized for shared UI/bridge IPC command (expected {} or {})",
                        caller_exe, AUTHORIZED_UI_EXE_PATH, AUTHORIZED_BRIDGE_EXE_PATH
                    ),
                })
            }
        }
    }
}

pub(super) fn dispatch_request(
    engine: &DaemonEngine,
    caller_exe: Option<&str>,
    req: IpcRequest,
) -> IpcResponse {
    let policy = caller_auth_policy_for_request(&req);
    if let Some(denied) = authorize_caller_policy(engine, caller_exe, policy) {
        return denied;
    }

    let store = engine.store();
    match req {
        IpcRequest::Ping => IpcResponse::Pong {
            daemon_version: env!("CARGO_PKG_VERSION").to_string(),
            protocol_version: ledr_proto::IPC_PROTOCOL_VERSION,
        },
        IpcRequest::GetFlightRecorder {
            limit,
            process_instance_id,
        } => match store.query_flight_recorder(limit, process_instance_id.as_deref()) {
            Ok(snapshot) => IpcResponse::FlightRecorder(snapshot),
            Err(err) => store_error_response(err),
        },
        IpcRequest::GetAlerts { status, limit } => match store.list_alerts(status, limit) {
            Ok(alerts) => IpcResponse::Alerts(alerts),
            Err(err) => store_error_response(err),
        },
        IpcRequest::ListRules { scope } => match store.list_rules(scope) {
            Ok(rules) => IpcResponse::Rules(rules),
            Err(err) => store_error_response(err),
        },
        IpcRequest::ListScopedRules { scope } => match store.list_scoped_rules(scope) {
            Ok(rules) => IpcResponse::ScopedRules(rules),
            Err(err) => store_error_response(err),
        },
        IpcRequest::GetPipelineMetrics => IpcResponse::Metrics(engine.metrics()),
        IpcRequest::CheckDomainRisk { domain } => {
            let assessment = engine.assess_domain(&domain);
            IpcResponse::DomainRisk {
                domain: assessment.domain,
                is_nrd: assessment.is_nrd,
                is_homograph: assessment.is_homograph,
                matched_brand: assessment.matched_brand,
            }
        }
        IpcRequest::ResolveAlert { alert_id, decision } => resolve_alert_ipc_response(
            engine,
            "ResolveAlert",
            &alert_id,
            decision,
            AllowPermanentPathMode::Exact,
        ),
        IpcRequest::ResolveAlertWithOptions {
            alert_id,
            decision,
            path_mode,
        } => resolve_alert_ipc_response(
            engine,
            "ResolveAlertWithOptions",
            &alert_id,
            decision,
            path_mode,
        ),
        IpcRequest::ResolveAlertScoped {
            alert_id,
            decision,
            scope_to_package,
        } => resolve_alert_scoped_ipc_response(engine, &alert_id, decision, scope_to_package),
        IpcRequest::UpsertRule { rule } => match engine.upsert_policy_rule(&rule) {
            Ok(_report) => IpcResponse::Ack {
                message: format!("upserted rule {}", rule.rule_id),
            },
            Err(err) => policy_rule_error_response(err),
        },
        IpcRequest::DeleteRule { rule_id } => match engine.delete_policy_rule(&rule_id) {
            Ok((true, _report)) => IpcResponse::Ack {
                message: format!("deleted rule {rule_id}"),
            },
            Ok((false, _)) => IpcResponse::Error {
                code: "NOT_FOUND".to_string(),
                message: format!("rule {rule_id} not found"),
            },
            Err(err) => policy_rule_error_response(err),
        },
        IpcRequest::UpsertScopedRule { rule } => match engine.upsert_scoped_policy_rule(&rule) {
            Ok(_report) => IpcResponse::Ack {
                message: format!("upserted scoped rule {}", rule.rule_id),
            },
            Err(err) => policy_rule_error_response(err),
        },
        IpcRequest::DeleteScopedRule { rule_id } => {
            match engine.delete_scoped_policy_rule(&rule_id) {
                Ok((true, _report)) => IpcResponse::Ack {
                    message: format!("deleted scoped rule {rule_id}"),
                },
                Ok((false, _)) => IpcResponse::Error {
                    code: "NOT_FOUND".to_string(),
                    message: format!("scoped rule {rule_id} not found"),
                },
                Err(err) => policy_rule_error_response(err),
            }
        }
        IpcRequest::ReportDownloadOrigin {
            file_path,
            tab_url,
            frame_url,
            referrer_url,
            downloaded_at_ms,
        } => match engine.record_browser_download_origin(
            &file_path,
            &tab_url,
            frame_url.as_deref(),
            referrer_url.as_deref(),
            downloaded_at_ms,
        ) {
            Ok(_) => IpcResponse::Ack {
                message: "recorded download origin".to_string(),
            },
            Err(err) => browser_report_error_response(err),
        },
        IpcRequest::ReportBrowserEvent {
            event_type,
            url,
            details,
            timestamp_ms,
        } => match engine.record_browser_event(event_type, &url, details.as_deref(), timestamp_ms) {
            Ok(BrowserEventOutcome::Recorded(alert)) => IpcResponse::Ack {
                message: format!("recorded browser event {}", alert.alert_id),
            },
            Ok(BrowserEventOutcome::Deduplicated) => IpcResponse::Ack {
                message: "browser event deduplicated".to_string(),
            },
            Err(err) => browser_report_error_response(err),
        },
    }
}

pub(super) fn browser_report_error_response(err: BrowserReportError) -> IpcResponse {
    match err {
        BrowserReportError::Invalid(msg) => IpcResponse::Error {
            code: "INVALID_REQUEST".to_string(),
            message: msg,
        },
        BrowserReportError::Store(err) => store_error_response(err),
        BrowserReportError::Cancelled => IpcResponse::Error {
            code: "CANCELLED".to_string(),
            message: "browser report cancelled".to_string(),
        },
    }
}

fn resolve_alert_scoped_ipc_response(
    engine: &DaemonEngine,
    alert_id: &str,
    decision: AlertDecision,
    scope_to_package: bool,
) -> IpcResponse {
    tracing::info!(
        alert_id = %alert_id,
        decision = decision_label(&decision),
        scope_to_package,
        request = "ResolveAlertScoped",
        "received alert resolve IPC request"
    );
    let wants_block_rule =
        matches!(decision, AlertDecision::TerminateAndBlock { add_block_rule: true });
    format_resolve_alert_outcome(
        alert_id,
        "ResolveAlertScoped",
        wants_block_rule,
        scope_to_package,
        engine.resolve_alert_scoped_with_outcome(alert_id, decision, scope_to_package),
    )
}

fn format_resolve_alert_outcome(
    alert_id: &str,
    request_name: &str,
    wants_block_rule: bool,
    scope_to_package: bool,
    res: Result<crate::engine::ResolvedAlertOutcome, String>,
) -> IpcResponse {
    match res {
        Ok(outcome) => {
            tracing::info!(
                alert_id = %outcome.alert.alert_id,
                source_layer = %outcome.alert.source_layer,
                status = %outcome.alert.status.as_db_str(),
                saved_rule_id = ?outcome.saved_rule_id,
                request = request_name,
                "completed alert resolve IPC request"
            );
            let mut message = format!(
                "alert {} resolved to {}",
                outcome.alert.alert_id,
                outcome.alert.status.as_db_str()
            );
            if let Some(rule_id) = outcome.saved_rule_id.as_deref() {
                message.push_str(&format!("; rule {rule_id} saved"));
            } else if wants_block_rule {
                if scope_to_package {
                    message.push_str(
                        "; no scoped NetworkBlock rule saved (non-AppContainer or unresolved package)",
                    );
                } else {
                    message.push_str("; no NetworkBlock rule saved (executable path unresolved)");
                }
            }
            IpcResponse::Ack { message }
        }
        Err(msg) => {
            let code = if msg.contains("not found") {
                "NOT_FOUND"
            } else if msg.contains("already resolved") {
                "ALREADY_RESOLVED"
            } else {
                "RESOLVE_ERROR"
            };
            tracing::warn!(
                alert_id = %alert_id,
                code = code,
                error = %msg,
                request = request_name,
                "alert resolve IPC request failed"
            );
            IpcResponse::Error {
                code: code.to_string(),
                message: msg,
            }
        }
    }
}

fn policy_rule_error_response(err: PolicyRuleError) -> IpcResponse {
    match err {
        PolicyRuleError::Invalid(msg) => IpcResponse::Error {
            code: "INVALID_RULE".to_string(),
            message: msg,
        },
        PolicyRuleError::FirewallSync(msg) => IpcResponse::Error {
            code: "WFP_SYNC_ERROR".to_string(),
            message: msg,
        },
        PolicyRuleError::Store(err) => store_error_response(err),
    }
}

fn resolve_alert_ipc_response(
    engine: &DaemonEngine,
    request_name: &str,
    alert_id: &str,
    decision: AlertDecision,
    path_mode: AllowPermanentPathMode,
) -> IpcResponse {
    tracing::info!(
        alert_id = %alert_id,
        decision = decision_label(&decision),
        path_mode = ?path_mode,
        request = request_name,
        "received alert resolve IPC request"
    );
    let wants_block_rule =
        matches!(decision, AlertDecision::TerminateAndBlock { add_block_rule: true });
    format_resolve_alert_outcome(
        alert_id,
        request_name,
        wants_block_rule,
        false,
        engine.resolve_alert_with_options_and_outcome(alert_id, decision, path_mode),
    )
}

fn decision_label(decision: &AlertDecision) -> &'static str {
    match decision {
        AlertDecision::AllowOnce => "AllowOnce",
        AlertDecision::AllowPermanent { .. } => "AllowPermanent",
        AlertDecision::TerminateAndBlock {
            add_block_rule: true,
        } => "TerminateAndBlock(add_block_rule=true)",
        AlertDecision::TerminateAndBlock {
            add_block_rule: false,
        } => "TerminateAndBlock(add_block_rule=false)",
    }
}

fn store_error_response(err: ledr_store::StoreError) -> IpcResponse {
    IpcResponse::Error {
        code: "STORE_ERROR".to_string(),
        message: err.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use ledr_proto::{
        ActiveDefenseController, AlertDecision, AlertRecord, AlertSeverity, AlertStatus,
        AllowPermanentPathMode, AllowlistRuleRecord, AuthenticodeInfo, BrowserSecurityEventType,
        IpcRequest, IpcResponse, ProcessIdentity, RuleScope, AUTHORIZED_BRIDGE_EXE_PATH,
        AUTHORIZED_UI_EXE_PATH,
    };
    use ledr_rules::{BinaryIdentity, EarlyPruner, SigmaEngine};
    use ledr_store::LedrStore;

    use crate::engine::{BinaryInspector, DaemonConfig, DaemonEngine};
    use crate::notify::NoopNotificationDispatcher;

    use super::{
        authorize_caller_policy, caller_auth_policy_for_request, dispatch_request, CallerAuthPolicy,
    };

    struct NoopDefense;

    impl ActiveDefenseController for NoopDefense {
        fn suspend_process(&self, _: &ProcessIdentity, _: bool) -> Result<(), String> {
            Ok(())
        }

        fn resume_process(&self, _: &ProcessIdentity) -> Result<(), String> {
            Ok(())
        }

        fn terminate_process(&self, _: &ProcessIdentity, _: bool) -> Result<(), String> {
            Ok(())
        }

        fn add_wfp_app_rule(&self, _: &Path, _: Option<IpAddr>, _: bool) -> Result<u64, String> {
            Ok(1)
        }

        fn add_wfp_scoped_app_rule(
            &self,
            _: &Path,
            _: Option<&str>,
            _: Option<IpAddr>,
            _: bool,
        ) -> Result<u64, String> {
            Ok(1)
        }

        fn remove_wfp_rule(&self, _: u64) -> Result<(), String> {
            Ok(())
        }
    }

    struct SpyBinaryInspector {
        cached_calls: AtomicUsize,
        uncached_calls: AtomicUsize,
        authenticode: Option<AuthenticodeInfo>,
    }

    impl SpyBinaryInspector {
        fn with_authenticode(authenticode: Option<AuthenticodeInfo>) -> Self {
            Self {
                cached_calls: AtomicUsize::new(0),
                uncached_calls: AtomicUsize::new(0),
                authenticode,
            }
        }

        fn cached_calls(&self) -> usize {
            self.cached_calls.load(Ordering::Acquire)
        }

        fn uncached_calls(&self) -> usize {
            self.uncached_calls.load(Ordering::Acquire)
        }
    }

    impl BinaryInspector for SpyBinaryInspector {
        fn inspect(&self, exe_path: &str) -> BinaryIdentity {
            self.cached_calls.fetch_add(1, Ordering::AcqRel);
            BinaryIdentity {
                exe_path: exe_path.to_string(),
                sha256: None,
                authenticode: self.authenticode.clone(),
            }
        }

        fn inspect_uncached(&self, exe_path: &str) -> BinaryIdentity {
            self.uncached_calls.fetch_add(1, Ordering::AcqRel);
            BinaryIdentity {
                exe_path: exe_path.to_string(),
                sha256: None,
                authenticode: self.authenticode.clone(),
            }
        }
    }

    fn test_authenticode() -> AuthenticodeInfo {
        AuthenticodeInfo {
            signer_subject: "CN=LocalEDR Test".to_string(),
            root_thumbprint: "0123456789ABCDEF0123456789ABCDEF01234567".to_string(),
        }
    }

    fn build_engine(
        dev_mode_bypass_ui_auth: bool,
        inspector: Arc<SpyBinaryInspector>,
    ) -> Arc<DaemonEngine> {
        let store = LedrStore::open_in_memory().expect("open in-memory store");
        let sigma = SigmaEngine::from_rules(Vec::new()).expect("empty rules");
        let pruner = EarlyPruner::default();
        DaemonEngine::start_with_dependencies(
            store,
            sigma,
            pruner,
            DaemonConfig {
                dev_mode_bypass_ui_auth,
                ..DaemonConfig::default()
            },
            Arc::new(NoopDefense),
            Arc::new(NoopNotificationDispatcher),
            inspector,
        )
    }

    fn sample_rule() -> AllowlistRuleRecord {
        AllowlistRuleRecord {
            rule_id: "R-DISPATCH-TEST".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: r"C:\Windows\System32\notepad.exe".to_string(),
            sha256: Some("a".repeat(64)),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("198.51.100.20".to_string()),
            created_by: "dispatch_test".to_string(),
            created_at_ms: 1_750_000_000_000,
        }
    }

    fn all_sample_requests() -> Vec<(&'static str, CallerAuthPolicy, IpcRequest)> {
        vec![
            ("Ping", CallerAuthPolicy::Public, IpcRequest::Ping),
            (
                "ResolveAlert",
                CallerAuthPolicy::UiOnly,
                IpcRequest::ResolveAlert {
                    alert_id: "missing-alert".to_string(),
                    decision: AlertDecision::AllowOnce,
                },
            ),
            (
                "ResolveAlertWithOptions",
                CallerAuthPolicy::UiOnly,
                IpcRequest::ResolveAlertWithOptions {
                    alert_id: "missing-alert".to_string(),
                    decision: AlertDecision::AllowPermanent {
                        use_signer_if_available: true,
                        allow_dest: None,
                    },
                    path_mode: AllowPermanentPathMode::WindowsAppsVersionWildcard,
                },
            ),
            (
                "ResolveAlertScoped",
                CallerAuthPolicy::UiOnly,
                IpcRequest::ResolveAlertScoped {
                    alert_id: "missing-alert".to_string(),
                    decision: AlertDecision::AllowOnce,
                    scope_to_package: true,
                },
            ),
            (
                "UpsertRule",
                CallerAuthPolicy::UiOnly,
                IpcRequest::UpsertRule {
                    rule: sample_rule(),
                },
            ),
            (
                "DeleteRule",
                CallerAuthPolicy::UiOnly,
                IpcRequest::DeleteRule {
                    rule_id: "R-DISPATCH-TEST".to_string(),
                },
            ),
            (
                "UpsertScopedRule",
                CallerAuthPolicy::UiOnly,
                IpcRequest::UpsertScopedRule {
                    rule: ledr_proto::ScopedPolicyRuleRecord {
                        rule_id: "SC-DISPATCH-TEST".to_string(),
                        scope: RuleScope::NetworkBlock,
                        exe_path_pattern: r"C:\Windows\System32\backgroundTaskHost.exe".to_string(),
                        sha256: None,
                        signer_subject: None,
                        root_thumbprint: None,
                        allowed_target: None,
                        package_family_name: None,
                        package_sid: Some("S-1-15-2-100-200".to_string()),
                        command_line_pattern: None,
                        created_at_ms: 1_750_000_000_000,
                        created_by: "dispatch_test".to_string(),
                    },
                },
            ),
            (
                "DeleteScopedRule",
                CallerAuthPolicy::UiOnly,
                IpcRequest::DeleteScopedRule {
                    rule_id: "SC-DISPATCH-TEST".to_string(),
                },
            ),
            (
                "GetFlightRecorder",
                CallerAuthPolicy::UiOnly,
                IpcRequest::GetFlightRecorder {
                    limit: 10,
                    process_instance_id: None,
                },
            ),
            (
                "GetAlerts",
                CallerAuthPolicy::UiOnly,
                IpcRequest::GetAlerts {
                    status: None,
                    limit: 10,
                },
            ),
            (
                "ListRules",
                CallerAuthPolicy::UiOnly,
                IpcRequest::ListRules { scope: None },
            ),
            (
                "ListScopedRules",
                CallerAuthPolicy::UiOnly,
                IpcRequest::ListScopedRules { scope: None },
            ),
            (
                "GetPipelineMetrics",
                CallerAuthPolicy::UiOnly,
                IpcRequest::GetPipelineMetrics,
            ),
            (
                "ReportDownloadOrigin",
                CallerAuthPolicy::BridgeOnly,
                IpcRequest::ReportDownloadOrigin {
                    file_path: r"C:\Users\test\Downloads\sample.exe".to_string(),
                    tab_url: "https://example.invalid/download".to_string(),
                    frame_url: None,
                    referrer_url: None,
                    downloaded_at_ms: 1_750_000_000_001,
                },
            ),
            (
                "ReportBrowserEvent",
                CallerAuthPolicy::BridgeOnly,
                IpcRequest::ReportBrowserEvent {
                    event_type: BrowserSecurityEventType::ClickFixPastejacking,
                    url: "https://example.invalid/page".to_string(),
                    details: Some("test".to_string()),
                    timestamp_ms: 1_750_000_000_002,
                },
            ),
            (
                "CheckDomainRisk",
                CallerAuthPolicy::UiOrBridge,
                IpcRequest::CheckDomainRisk {
                    domain: "micros0ft.com".to_string(),
                },
            ),
        ]
    }

    fn assert_not_auth_rejection(label: &str, resp: &IpcResponse) {
        if let IpcResponse::Error { code, .. } = resp {
            assert!(
                code != "UNAUTHORIZED" && code != "UNAUTHORIZED_CALLER",
                "{label} unexpectedly failed auth: {resp:?}"
            );
        }
    }

    #[tokio::test]
    async fn caller_auth_policy_matrix_enforces_roles_and_inspect_uncached() {
        let inspector = Arc::new(SpyBinaryInspector::with_authenticode(Some(
            test_authenticode(),
        )));
        let engine = build_engine(false, Arc::clone(&inspector));
        let rogue_caller = r"C:\Temp\rogue.exe";

        for (label, expected_policy, req) in all_sample_requests() {
            assert_eq!(
                caller_auth_policy_for_request(&req),
                expected_policy,
                "{label} policy mismatch"
            );

            match expected_policy {
                CallerAuthPolicy::Public => {
                    for caller in [
                        None,
                        Some(rogue_caller),
                        Some(AUTHORIZED_UI_EXE_PATH),
                        Some(AUTHORIZED_BRIDGE_EXE_PATH),
                    ] {
                        let before = inspector.uncached_calls();
                        let resp = dispatch_request(&engine, caller, req.clone());
                        assert!(matches!(resp, IpcResponse::Pong { .. }), "{label}: {resp:?}");
                        assert_eq!(inspector.uncached_calls(), before);
                    }
                }
                CallerAuthPolicy::UiOnly => {
                    let before = inspector.uncached_calls();
                    let ok_resp =
                        dispatch_request(&engine, Some(AUTHORIZED_UI_EXE_PATH), req.clone());
                    assert_not_auth_rejection(label, &ok_resp);
                    assert_eq!(inspector.uncached_calls(), before + 1);

                    // Cross-role (bridge) and untrusted/missing callers must be rejected with UNAUTHORIZED.
                    for denied_caller in [
                        Some(AUTHORIZED_BRIDGE_EXE_PATH),
                        Some(rogue_caller),
                        None,
                    ] {
                        let resp = dispatch_request(&engine, denied_caller, req.clone());
                        assert!(
                            matches!(resp, IpcResponse::Error { ref code, .. } if code == "UNAUTHORIZED"),
                            "{label} must reject {denied_caller:?} with UNAUTHORIZED, got {resp:?}"
                        );
                    }
                }
                CallerAuthPolicy::BridgeOnly => {
                    let before = inspector.uncached_calls();
                    let ok_resp =
                        dispatch_request(&engine, Some(AUTHORIZED_BRIDGE_EXE_PATH), req.clone());
                    assert_not_auth_rejection(label, &ok_resp);
                    assert_eq!(inspector.uncached_calls(), before + 1);

                    // Cross-role (UI) and untrusted/missing callers must be rejected with UNAUTHORIZED_CALLER.
                    for denied_caller in [Some(AUTHORIZED_UI_EXE_PATH), Some(rogue_caller), None] {
                        let resp = dispatch_request(&engine, denied_caller, req.clone());
                        assert!(
                            matches!(resp, IpcResponse::Error { ref code, .. } if code == "UNAUTHORIZED_CALLER"),
                            "{label} must reject {denied_caller:?} with UNAUTHORIZED_CALLER, got {resp:?}"
                        );
                    }
                }
                CallerAuthPolicy::UiOrBridge => {
                    let before = inspector.uncached_calls();
                    let ui_resp =
                        dispatch_request(&engine, Some(AUTHORIZED_UI_EXE_PATH), req.clone());
                    assert!(
                        matches!(ui_resp, IpcResponse::DomainRisk { .. }),
                        "{label} UI caller must succeed, got {ui_resp:?}"
                    );
                    assert_eq!(inspector.uncached_calls(), before + 1);

                    let bridge_resp =
                        dispatch_request(&engine, Some(AUTHORIZED_BRIDGE_EXE_PATH), req.clone());
                    assert!(
                        matches!(bridge_resp, IpcResponse::DomainRisk { .. }),
                        "{label} bridge caller must succeed, got {bridge_resp:?}"
                    );
                    assert_eq!(inspector.uncached_calls(), before + 2);

                    for denied_caller in [Some(rogue_caller), None] {
                        let resp = dispatch_request(&engine, denied_caller, req.clone());
                        assert!(
                            matches!(resp, IpcResponse::Error { ref code, .. } if code == "UNAUTHORIZED"),
                            "{label} must reject {denied_caller:?} with UNAUTHORIZED, got {resp:?}"
                        );
                    }
                }
            }
        }

        // Verify `authorize_caller_policy` and repeated `dispatch_request` calls never invoke
        // cached `inspect()` and always re-verify via `inspect_uncached()`.
        let cached_before_auth = inspector.cached_calls();
        let uncached_before_auth = inspector.uncached_calls();
        assert!(authorize_caller_policy(
            &engine,
            Some(AUTHORIZED_UI_EXE_PATH),
            CallerAuthPolicy::UiOnly
        )
        .is_none());
        assert!(authorize_caller_policy(
            &engine,
            Some(AUTHORIZED_BRIDGE_EXE_PATH),
            CallerAuthPolicy::BridgeOnly
        )
        .is_none());
        assert!(authorize_caller_policy(
            &engine,
            Some(AUTHORIZED_UI_EXE_PATH),
            CallerAuthPolicy::UiOrBridge
        )
        .is_none());
        assert!(authorize_caller_policy(
            &engine,
            Some(AUTHORIZED_BRIDGE_EXE_PATH),
            CallerAuthPolicy::UiOrBridge
        )
        .is_none());
        assert_eq!(inspector.cached_calls(), cached_before_auth);
        assert_eq!(inspector.uncached_calls(), uncached_before_auth + 4);

        let before_repeat_cached = inspector.cached_calls();
        let before_repeat_uncached = inspector.uncached_calls();
        for _ in 0..2 {
            let resp = dispatch_request(
                &engine,
                Some(AUTHORIZED_UI_EXE_PATH),
                IpcRequest::GetPipelineMetrics,
            );
            assert!(matches!(resp, IpcResponse::Metrics(_)));
        }
        assert_eq!(inspector.uncached_calls(), before_repeat_uncached + 2);
        assert_eq!(inspector.cached_calls(), before_repeat_cached);

        engine.shutdown_and_flush().await.expect("shutdown");
    }

    #[tokio::test]
    async fn caller_auth_policy_fails_closed_when_uncached_authenticode_is_missing() {
        let inspector = Arc::new(SpyBinaryInspector::with_authenticode(None));
        let engine = build_engine(false, Arc::clone(&inspector));

        let ui_denied = authorize_caller_policy(
            &engine,
            Some(AUTHORIZED_UI_EXE_PATH),
            CallerAuthPolicy::UiOnly,
        );
        assert!(matches!(
            ui_denied,
            Some(IpcResponse::Error { ref code, .. }) if code == "UNAUTHORIZED"
        ));

        let bridge_denied = authorize_caller_policy(
            &engine,
            Some(AUTHORIZED_BRIDGE_EXE_PATH),
            CallerAuthPolicy::BridgeOnly,
        );
        assert!(matches!(
            bridge_denied,
            Some(IpcResponse::Error { ref code, .. }) if code == "UNAUTHORIZED_CALLER"
        ));

        let shared_ui_denied = authorize_caller_policy(
            &engine,
            Some(AUTHORIZED_UI_EXE_PATH),
            CallerAuthPolicy::UiOrBridge,
        );
        assert!(matches!(
            shared_ui_denied,
            Some(IpcResponse::Error { ref code, .. }) if code == "UNAUTHORIZED"
        ));

        let shared_bridge_denied = authorize_caller_policy(
            &engine,
            Some(AUTHORIZED_BRIDGE_EXE_PATH),
            CallerAuthPolicy::UiOrBridge,
        );
        assert!(matches!(
            shared_bridge_denied,
            Some(IpcResponse::Error { ref code, .. }) if code == "UNAUTHORIZED"
        ));

        assert_eq!(inspector.cached_calls(), 0);
        // UiOnly (1) + BridgeOnly (1) + UiOrBridge for UI (1) + UiOrBridge for Bridge (1) = 4 uncached inspections.
        assert_eq!(inspector.uncached_calls(), 4);

        engine.shutdown_and_flush().await.expect("shutdown");
    }

    #[tokio::test]
    async fn caller_auth_policy_allows_all_requests_when_dev_bypass_enabled() {
        let inspector = Arc::new(SpyBinaryInspector::with_authenticode(None));
        let engine = build_engine(true, Arc::clone(&inspector));

        for policy in [
            CallerAuthPolicy::Public,
            CallerAuthPolicy::UiOnly,
            CallerAuthPolicy::BridgeOnly,
            CallerAuthPolicy::UiOrBridge,
        ] {
            assert!(authorize_caller_policy(&engine, None, policy).is_none());
            assert!(authorize_caller_policy(&engine, Some(r"C:\Temp\rogue.exe"), policy).is_none());
        }
        assert_eq!(inspector.cached_calls(), 0);
        assert_eq!(inspector.uncached_calls(), 0);

        for (label, _, req) in all_sample_requests() {
            let resp = dispatch_request(&engine, None, req);
            assert_not_auth_rejection(label, &resp);
        }
        assert_eq!(inspector.uncached_calls(), 0);

        engine.shutdown_and_flush().await.expect("shutdown");
    }

    #[tokio::test]
    async fn resolve_alert_with_options_enforces_ui_only_and_dispatches_wildcard() {
        let inspector = Arc::new(SpyBinaryInspector::with_authenticode(Some(
            test_authenticode(),
        )));
        let engine = build_engine(false, Arc::clone(&inspector));

        let store_exe = r"C:\Program Files\WindowsApps\Contoso.StoreApp_1.2.3.0_x64__8wekyb3d8bbwe\StoreApp.exe";
        let alert_id = "ALERT-WA-DISPATCH-01";
        let alert = AlertRecord {
            alert_id: alert_id.to_string(),
            timestamp_ms: 1_750_000_000_000,
            severity: AlertSeverity::Medium,
            source_layer: "LAYER_3_NETWORK".to_string(),
            rule_id: "NET_OUTBOUND_ENFORCE".to_string(),
            title: "Outbound connection".to_string(),
            process_instance_id: Some("4200:133000000000000000".to_string()),
            process_suspended: false,
            status: AlertStatus::Pending,
            context_json: serde_json::json!({
                "exe_path": store_exe,
                "signer_subject": "CN=Contoso Store Publisher",
                "root_thumbprint": "0123456789ABCDEF0123456789ABCDEF01234567",
                "dst_ip": "198.51.100.44",
                "dst_port": 443
            })
            .to_string(),
            resolved_at_ms: None,
        };
        engine.store().record_alert(&alert).expect("record alert");

        let req = IpcRequest::ResolveAlertWithOptions {
            alert_id: alert_id.to_string(),
            decision: AlertDecision::AllowPermanent {
                use_signer_if_available: true,
                allow_dest: None,
            },
            path_mode: AllowPermanentPathMode::WindowsAppsVersionWildcard,
        };
        assert_eq!(
            caller_auth_policy_for_request(&req),
            CallerAuthPolicy::UiOnly
        );

        for denied in [
            None,
            Some(r"C:\Temp\rogue.exe"),
            Some(AUTHORIZED_BRIDGE_EXE_PATH),
        ] {
            let resp = dispatch_request(&engine, denied, req.clone());
            assert!(
                matches!(resp, IpcResponse::Error { ref code, .. } if code == "UNAUTHORIZED"),
                "expected UNAUTHORIZED for {denied:?}, got {resp:?}"
            );
        }

        // Alert must still be Pending after unauthorized rejections.
        assert_eq!(
            engine
                .store()
                .get_alert(alert_id)
                .expect("query alert")
                .expect("alert exists")
                .status,
            AlertStatus::Pending
        );

        // Authorized UI caller succeeds and saves the wildcard rule.
        let ok_resp = dispatch_request(&engine, Some(AUTHORIZED_UI_EXE_PATH), req.clone());
        assert!(
            matches!(ok_resp, IpcResponse::Ack { ref message } if message.contains("APPROVED_RULE") && message.contains("RULE-ALLOW-")),
            "expected Ack with saved rule, got {ok_resp:?}"
        );

        let rules = engine
            .store()
            .list_rules(Some(RuleScope::NetworkAllow))
            .expect("list NetworkAllow");
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0].exe_path_pattern,
            r"C:\Program Files\WindowsApps\Contoso.StoreApp_*_x64__8wekyb3d8bbwe\StoreApp.exe"
        );
        assert_eq!(rules[0].sha256, None);

        // Second attempt on resolved alert maps to ALREADY_RESOLVED.
        let dup_resp = dispatch_request(&engine, Some(AUTHORIZED_UI_EXE_PATH), req);
        assert!(
            matches!(dup_resp, IpcResponse::Error { ref code, .. } if code == "ALREADY_RESOLVED"),
            "expected ALREADY_RESOLVED, got {dup_resp:?}"
        );

        // Missing alert maps to NOT_FOUND.
        let missing_resp = dispatch_request(
            &engine,
            Some(AUTHORIZED_UI_EXE_PATH),
            IpcRequest::ResolveAlertWithOptions {
                alert_id: "missing-wa-alert".to_string(),
                decision: AlertDecision::AllowOnce,
                path_mode: AllowPermanentPathMode::Exact,
            },
        );
        assert!(
            matches!(missing_resp, IpcResponse::Error { ref code, .. } if code == "NOT_FOUND"),
            "expected NOT_FOUND, got {missing_resp:?}"
        );

        // Invalid path_mode + decision combination on pending alert maps to RESOLVE_ERROR.
        let bad_alert = AlertRecord {
            alert_id: "ALERT-WA-DISPATCH-02".to_string(),
            ..alert
        };
        engine
            .store()
            .record_alert(&bad_alert)
            .expect("record bad_alert");
        let err_resp = dispatch_request(
            &engine,
            Some(AUTHORIZED_UI_EXE_PATH),
            IpcRequest::ResolveAlertWithOptions {
                alert_id: "ALERT-WA-DISPATCH-02".to_string(),
                decision: AlertDecision::AllowOnce,
                path_mode: AllowPermanentPathMode::WindowsAppsVersionWildcard,
            },
        );
        assert!(
            matches!(err_resp, IpcResponse::Error { ref code, .. } if code == "RESOLVE_ERROR"),
            "expected RESOLVE_ERROR, got {err_resp:?}"
        );

        engine.shutdown_and_flush().await.expect("shutdown");
    }

    #[tokio::test]
    async fn scoped_rule_crud_and_resolve_alert_scoped_enforce_ui_only_and_isolate_legacy() {
        let inspector = Arc::new(SpyBinaryInspector::with_authenticode(Some(
            test_authenticode(),
        )));
        let engine = build_engine(false, Arc::clone(&inspector));
        let bth_exe = r"C:\Windows\System32\backgroundTaskHost.exe";
        let sid_a = "S-1-15-2-100-200-300";

        let scoped_rule = ledr_proto::ScopedPolicyRuleRecord {
            rule_id: "SC-ROUNDTRIP-01".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: bth_exe.to_string(),
            sha256: None,
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("evil.example".to_string()),
            package_family_name: Some("Contoso.PkgA_8wekyb3d8bbwe".to_string()),
            package_sid: Some(sid_a.to_string()),
            command_line_pattern: None,
            created_at_ms: 1_750_000_000_100,
            created_by: "dispatch_test".to_string(),
        };

        // 1. Upsert -> ListScopedRules -> legacy ListRules untouched -> Delete -> second Delete NOT_FOUND.
        let upsert_req = IpcRequest::UpsertScopedRule {
            rule: scoped_rule.clone(),
        };
        assert_eq!(
            caller_auth_policy_for_request(&upsert_req),
            CallerAuthPolicy::UiOnly
        );
        for denied in [None, Some(r"C:\Temp\rogue.exe"), Some(AUTHORIZED_BRIDGE_EXE_PATH)] {
            let resp = dispatch_request(&engine, denied, upsert_req.clone());
            assert!(
                matches!(resp, IpcResponse::Error { ref code, .. } if code == "UNAUTHORIZED"),
                "expected UNAUTHORIZED for {denied:?}, got {resp:?}"
            );
        }
        let upsert_ok = dispatch_request(&engine, Some(AUTHORIZED_UI_EXE_PATH), upsert_req);
        assert!(
            matches!(upsert_ok, IpcResponse::Ack { ref message } if message.contains("SC-ROUNDTRIP-01")),
            "expected Ack for UpsertScopedRule, got {upsert_ok:?}"
        );

        let list_scoped = dispatch_request(
            &engine,
            Some(AUTHORIZED_UI_EXE_PATH),
            IpcRequest::ListScopedRules { scope: None },
        );
        match list_scoped {
            IpcResponse::ScopedRules(rules) => {
                assert_eq!(rules.len(), 1);
                assert_eq!(rules[0].rule_id, "SC-ROUNDTRIP-01");
            }
            other => panic!("expected ScopedRules response, got {other:?}"),
        }

        let list_legacy = dispatch_request(
            &engine,
            Some(AUTHORIZED_UI_EXE_PATH),
            IpcRequest::ListRules { scope: None },
        );
        match list_legacy {
            IpcResponse::Rules(rules) => assert!(rules.is_empty(), "legacy rules must stay isolated"),
            other => panic!("expected legacy Rules response, got {other:?}"),
        }

        let del_ok = dispatch_request(
            &engine,
            Some(AUTHORIZED_UI_EXE_PATH),
            IpcRequest::DeleteScopedRule {
                rule_id: "SC-ROUNDTRIP-01".to_string(),
            },
        );
        assert!(matches!(del_ok, IpcResponse::Ack { .. }), "got {del_ok:?}");

        let del_missing = dispatch_request(
            &engine,
            Some(AUTHORIZED_UI_EXE_PATH),
            IpcRequest::DeleteScopedRule {
                rule_id: "SC-ROUNDTRIP-01".to_string(),
            },
        );
        assert!(
            matches!(del_missing, IpcResponse::Error { ref code, .. } if code == "NOT_FOUND"),
            "expected NOT_FOUND on second delete, got {del_missing:?}"
        );

        // 2. ResolveAlertScoped enforces UiOnly and creates scoped NetworkAllow on authorized UI call.
        let alert_id = "ALERT-SCOPED-DISPATCH-01";
        let alert = AlertRecord {
            alert_id: alert_id.to_string(),
            timestamp_ms: 1_750_000_000_200,
            severity: AlertSeverity::Medium,
            source_layer: "LAYER_3_NETWORK".to_string(),
            rule_id: "NET_OUTBOUND_ENFORCE".to_string(),
            title: "Outbound connection".to_string(),
            process_instance_id: Some("4201:133000000000000000".to_string()),
            process_suspended: false,
            status: AlertStatus::Pending,
            context_json: serde_json::json!({
                "exe_path": bth_exe,
                "signer_subject": "CN=Microsoft Windows",
                "root_thumbprint": "0123456789ABCDEF0123456789ABCDEF01234567",
                "package_family_name": "Contoso.PkgA_8wekyb3d8bbwe",
                "package_sid": sid_a,
                "dst_ip": "198.51.100.44",
                "dst_port": 443
            })
            .to_string(),
            resolved_at_ms: None,
        };
        engine.store().record_alert(&alert).expect("record alert");
        let resolve_req = IpcRequest::ResolveAlertScoped {
            alert_id: alert_id.to_string(),
            decision: AlertDecision::AllowPermanent {
                use_signer_if_available: true,
                allow_dest: Some("api.contoso.com".to_string()),
            },
            scope_to_package: true,
        };
        assert_eq!(
            caller_auth_policy_for_request(&resolve_req),
            CallerAuthPolicy::UiOnly
        );
        for denied in [None, Some(r"C:\Temp\rogue.exe"), Some(AUTHORIZED_BRIDGE_EXE_PATH)] {
            let resp = dispatch_request(&engine, denied, resolve_req.clone());
            assert!(
                matches!(resp, IpcResponse::Error { ref code, .. } if code == "UNAUTHORIZED"),
                "expected UNAUTHORIZED for {denied:?}, got {resp:?}"
            );
        }
        let resolve_ok = dispatch_request(&engine, Some(AUTHORIZED_UI_EXE_PATH), resolve_req);
        assert!(
            matches!(resolve_ok, IpcResponse::Ack { ref message } if message.contains("APPROVED_RULE") && message.contains("RULE-SCOPED-ALLOW-")),
            "expected Ack with scoped rule, got {resolve_ok:?}"
        );
        assert!(engine.store().list_rules(None).expect("legacy rules").is_empty());
        assert_eq!(
            engine
                .store()
                .list_scoped_rules(Some(RuleScope::NetworkAllow))
                .expect("scoped rules")
                .len(),
            1
        );

        engine.shutdown_and_flush().await.expect("shutdown");
    }
}
