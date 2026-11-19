use crate::cli::LaunchMode;
use crate::defense_status::{LocalDefenseStatus, collect_local_defense_status};
use crate::ipc::{DomainRiskView, IpcClient};
use crate::tree;
use ledr_proto::{
    AlertDecision, AlertRecord, AlertStatus, AllowlistRuleRecord, FlightRecorderSnapshot,
    PipelineMetrics, RuleScope,
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

#[tauri::command]
pub(crate) async fn resolve_alert_action(
    client: tauri::State<'_, IpcClient>,
    alert_id: String,
    decision: AlertDecision,
) -> Result<String, String> {
    let client = client.inner().clone();
    tauri::async_runtime::spawn_blocking(move || client.resolve_alert(alert_id, decision))
        .await
        .map_err(|err| format!("IPC background task failed: {err}"))?
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
