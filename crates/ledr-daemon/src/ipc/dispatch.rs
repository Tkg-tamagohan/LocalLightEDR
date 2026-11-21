//! IPC request authorization enforcement and command dispatch to `DaemonEngine`.

use ledr_proto::{
    AlertDecision, IpcRequest, IpcResponse, AUTHORIZED_BRIDGE_EXE_PATH, AUTHORIZED_UI_EXE_PATH,
};

use crate::engine::{BrowserEventOutcome, BrowserReportError, DaemonEngine, PolicyRuleError};

use super::auth::verify_authorized_caller_binary;

pub(super) fn dispatch_request(
    engine: &DaemonEngine,
    caller_exe: Option<&str>,
    req: IpcRequest,
) -> IpcResponse {
    let cfg = engine.config();
    if req.requires_ui_authorization()
        && !verify_authorized_caller_binary(
            caller_exe,
            AUTHORIZED_UI_EXE_PATH,
            cfg.authorized_ui_sha256.as_deref(),
            cfg.authorized_ui_signer.as_deref(),
            cfg.authorized_ui_root_thumbprint.as_deref(),
            cfg.dev_mode_bypass_ui_auth,
        )
    {
        return IpcResponse::Error {
            code: "UNAUTHORIZED".to_string(),
            message: format!(
                "caller {:?} is not authorized for mutating IPC command (expected {})",
                caller_exe, AUTHORIZED_UI_EXE_PATH
            ),
        };
    }

    if matches!(
        req,
        IpcRequest::ReportDownloadOrigin { .. } | IpcRequest::ReportBrowserEvent { .. }
    ) && !verify_authorized_caller_binary(
        caller_exe,
        AUTHORIZED_BRIDGE_EXE_PATH,
        cfg.authorized_bridge_sha256.as_deref(),
        cfg.authorized_bridge_signer.as_deref(),
        cfg.authorized_bridge_root_thumbprint.as_deref(),
        cfg.dev_mode_bypass_ui_auth,
    ) {
        return IpcResponse::Error {
            code: "UNAUTHORIZED_CALLER".to_string(),
            message: format!(
                "caller {:?} is not authorized for browser bridge IPC command (expected {})",
                caller_exe, AUTHORIZED_BRIDGE_EXE_PATH
            ),
        };
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
        IpcRequest::ResolveAlert { alert_id, decision } => {
            let wants_block_rule =
                matches!(decision, AlertDecision::TerminateAndBlock { add_block_rule: true });
            match engine.resolve_alert_with_outcome(&alert_id, decision) {
                Ok(outcome) => {
                    let mut message = format!(
                        "alert {} resolved to {}",
                        outcome.alert.alert_id,
                        outcome.alert.status.as_db_str()
                    );
                    if let Some(rule_id) = outcome.saved_rule_id.as_deref() {
                        message.push_str(&format!("; rule {rule_id} saved"));
                    } else if wants_block_rule {
                        message.push_str("; no NetworkBlock rule saved (executable path unresolved)");
                    }
                    IpcResponse::Ack { message }
                },
                Err(msg) => {
                    let code = if msg.contains("not found") {
                        "NOT_FOUND"
                    } else if msg.contains("already resolved") {
                        "ALREADY_RESOLVED"
                    } else {
                        "RESOLVE_ERROR"
                    };
                    IpcResponse::Error {
                        code: code.to_string(),
                        message: msg,
                    }
                }
            }
        }
        IpcRequest::UpsertRule { rule } => match engine.upsert_policy_rule(&rule) {
            Ok(_report) => IpcResponse::Ack {
                message: format!("upserted rule {}", rule.rule_id),
            },
            Err(PolicyRuleError::Invalid(msg)) => IpcResponse::Error {
                code: "INVALID_RULE".to_string(),
                message: msg,
            },
            Err(PolicyRuleError::FirewallSync(msg)) => IpcResponse::Error {
                code: "WFP_SYNC_ERROR".to_string(),
                message: msg,
            },
            Err(PolicyRuleError::Store(err)) => store_error_response(err),
        },
        IpcRequest::DeleteRule { rule_id } => match engine.delete_policy_rule(&rule_id) {
            Ok((true, _report)) => IpcResponse::Ack {
                message: format!("deleted rule {rule_id}"),
            },
            Ok((false, _)) => IpcResponse::Error {
                code: "NOT_FOUND".to_string(),
                message: format!("rule {rule_id} not found"),
            },
            Err(PolicyRuleError::FirewallSync(msg)) => IpcResponse::Error {
                code: "WFP_SYNC_ERROR".to_string(),
                message: msg,
            },
            Err(PolicyRuleError::Invalid(msg)) => IpcResponse::Error {
                code: "INVALID_RULE".to_string(),
                message: msg,
            },
            Err(PolicyRuleError::Store(err)) => store_error_response(err),
        },
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
            Err(BrowserReportError::Invalid(msg)) => IpcResponse::Error {
                code: "INVALID_REQUEST".to_string(),
                message: msg,
            },
            Err(BrowserReportError::Store(err)) => store_error_response(err),
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
            Err(BrowserReportError::Invalid(msg)) => IpcResponse::Error {
                code: "INVALID_REQUEST".to_string(),
                message: msg,
            },
            Err(BrowserReportError::Store(err)) => store_error_response(err),
        },
    }
}

fn store_error_response(err: ledr_store::StoreError) -> IpcResponse {
    IpcResponse::Error {
        code: "STORE_ERROR".to_string(),
        message: err.to_string(),
    }
}
