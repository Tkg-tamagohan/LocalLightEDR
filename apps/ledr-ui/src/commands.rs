use crate::cli::LaunchMode;
use crate::defense_status::{LocalDefenseStatus, collect_local_defense_status};
use crate::ipc::{DomainRiskView, IpcClient};
use crate::tree;
use crate::updater::{
    AppUpdateManager, UpdaterStatusView, emit_updater_status, open_release_notes_url_validated,
};
use ledr_proto::{
    AlertDecision, AlertRecord, AlertStatus, AllowPermanentPathMode, AllowlistRuleRecord,
    FlightRecorderSnapshot, PipelineMetrics, RuleScope,
};

#[tauri::command]
pub(crate) async fn fetch_flight_recorder(
    client: tauri::State<'_, IpcClient>,
    limit: usize,
    process_instance_id: Option<String>,
) -> Result<FlightRecorderSnapshot, String> {
    let client = client.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        client.get_flight_recorder(limit, process_instance_id)
    })
    .await
    .map_err(|err| format!("IPC background task failed: {err}"))?
}

#[tauri::command]
pub(crate) async fn fetch_pipeline_metrics(
    client: tauri::State<'_, IpcClient>,
) -> Result<PipelineMetrics, String> {
    let client = client.inner().clone();
    tauri::async_runtime::spawn_blocking(move || client.get_pipeline_metrics())
        .await
        .map_err(|err| format!("IPC background task failed: {err}"))?
}

#[tauri::command]
pub(crate) async fn fetch_alerts(
    client: tauri::State<'_, IpcClient>,
    status: Option<AlertStatus>,
    limit: usize,
) -> Result<Vec<AlertRecord>, String> {
    let client = client.inner().clone();
    tauri::async_runtime::spawn_blocking(move || client.get_alerts(status, limit))
        .await
        .map_err(|err| format!("IPC background task failed: {err}"))?
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ResolveAlertInvokePayload {
    pub alert_id: String,
    pub decision: AlertDecision,
    #[serde(default)]
    pub path_mode: AllowPermanentPathMode,
}

pub(crate) async fn execute_resolve_alert_action(
    client: IpcClient,
    payload: ResolveAlertInvokePayload,
) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        client.resolve_alert_with_options(payload.alert_id, payload.decision, payload.path_mode)
    })
    .await
    .map_err(|err| format!("IPC background task failed: {err}"))?
}

#[tauri::command]
pub(crate) async fn resolve_alert_action(
    client: tauri::State<'_, IpcClient>,
    alert_id: String,
    decision: AlertDecision,
    path_mode: Option<AllowPermanentPathMode>,
) -> Result<String, String> {
    let payload = ResolveAlertInvokePayload {
        alert_id,
        decision,
        path_mode: path_mode.unwrap_or_default(),
    };
    execute_resolve_alert_action(client.inner().clone(), payload).await
}

#[tauri::command]
pub(crate) async fn fetch_rules(
    client: tauri::State<'_, IpcClient>,
    scope: Option<RuleScope>,
) -> Result<Vec<AllowlistRuleRecord>, String> {
    let client = client.inner().clone();
    tauri::async_runtime::spawn_blocking(move || client.list_rules(scope))
        .await
        .map_err(|err| format!("IPC background task failed: {err}"))?
}

#[tauri::command]
pub(crate) async fn upsert_rule_action(
    client: tauri::State<'_, IpcClient>,
    rule: AllowlistRuleRecord,
) -> Result<String, String> {
    let client = client.inner().clone();
    tauri::async_runtime::spawn_blocking(move || client.upsert_rule(rule))
        .await
        .map_err(|err| format!("IPC background task failed: {err}"))?
}

#[tauri::command]
pub(crate) async fn delete_rule_action(
    client: tauri::State<'_, IpcClient>,
    rule_id: String,
) -> Result<String, String> {
    let client = client.inner().clone();
    tauri::async_runtime::spawn_blocking(move || client.delete_rule(rule_id))
        .await
        .map_err(|err| format!("IPC background task failed: {err}"))?
}

#[tauri::command]
pub(crate) async fn check_domain_risk_action(
    client: tauri::State<'_, IpcClient>,
    domain: String,
) -> Result<DomainRiskView, String> {
    let client = client.inner().clone();
    tauri::async_runtime::spawn_blocking(move || client.check_domain_risk(domain))
        .await
        .map_err(|err| format!("IPC background task failed: {err}"))?
}

#[tauri::command]
pub(crate) fn fetch_local_defense_status() -> LocalDefenseStatus {
    collect_local_defense_status()
}

#[tauri::command]
pub(crate) async fn ping_daemon(client: tauri::State<'_, IpcClient>) -> Result<String, String> {
    let client = client.inner().clone();
    tauri::async_runtime::spawn_blocking(move || client.ping())
        .await
        .map_err(|err| format!("IPC background task failed: {err}"))?
}

#[tauri::command]
pub(crate) fn get_launch_mode(mode: tauri::State<'_, LaunchMode>) -> LaunchMode {
    mode.inner().clone()
}

#[tauri::command]
pub(crate) fn build_process_tree_view(snapshot: FlightRecorderSnapshot) -> Vec<tree::ProcessTreeNode> {
    tree::build_process_tree(&snapshot)
}

#[tauri::command]
pub(crate) fn get_updater_status(manager: tauri::State<'_, AppUpdateManager>) -> UpdaterStatusView {
    manager.status()
}

#[tauri::command]
pub(crate) async fn check_for_updates(
    app: tauri::AppHandle,
    manager: tauri::State<'_, AppUpdateManager>,
) -> Result<UpdaterStatusView, String> {
    let mgr = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        mgr.check_for_updates_blocking_with(|view| emit_updater_status(&app, view))
    })
    .await
    .map_err(|err| format!("updater check task failed: {err}"))?
}

#[tauri::command]
pub(crate) async fn apply_update(
    app: tauri::AppHandle,
    manager: tauri::State<'_, AppUpdateManager>,
) -> Result<UpdaterStatusView, String> {
    let mgr = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        mgr.apply_update_blocking_with(|view| emit_updater_status(&app, view), None::<fn()>)
    })
    .await
    .map_err(|err| format!("updater apply task failed: {err}"))?
}

#[tauri::command]
pub(crate) async fn cancel_update_download(
    manager: tauri::State<'_, AppUpdateManager>,
) -> Result<UpdaterStatusView, String> {
    let mgr = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || mgr.cancel_active_operation())
        .await
        .map_err(|err| format!("updater cancel task failed: {err}"))
}

#[tauri::command]
pub(crate) fn trigger_startup_update_check(
    app: tauri::AppHandle,
    mode: tauri::State<'_, LaunchMode>,
    manager: tauri::State<'_, AppUpdateManager>,
) -> Result<(), String> {
    if !manager.should_trigger_startup_auto_check(mode.inner()) {
        return Ok(());
    }
    let mgr = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _ = mgr.check_for_updates_blocking_with(|view| emit_updater_status(&app, view));
    });
    Ok(())
}

#[tauri::command]
pub(crate) async fn open_release_notes_url(url: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || open_release_notes_url_validated(&url))
        .await
        .map_err(|err| format!("open release notes task failed: {err}"))?
}
