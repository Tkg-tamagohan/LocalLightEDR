#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod cli;
mod commands;
mod defense_status;
mod ipc;
mod notify;
#[cfg(test)]
mod tests;
mod tree;
mod uri_reg;

pub use cli::LaunchMode;
pub use notify::DISABLE_OS_TOAST_ENV;

use cli::parse_launch_mode;
use ipc::IpcClient;
use notify::dispatch_notify_oneshot;
use tauri::Manager;
use uri_reg::dispatch_register_uri;

fn run_gui(launch_mode: LaunchMode, ipc_client: IpcClient) -> Result<(), String> {
    let app = tauri::Builder::default()
        .manage(launch_mode)
        .manage(ipc_client)
        .invoke_handler(tauri::generate_handler![
            commands::fetch_flight_recorder,
            commands::fetch_pipeline_metrics,
            commands::fetch_alerts,
            commands::resolve_alert_action,
            commands::fetch_rules,
            commands::upsert_rule_action,
            commands::delete_rule_action,
            commands::check_domain_risk_action,
            commands::fetch_local_defense_status,
            commands::ping_daemon,
            commands::get_launch_mode,
            commands::build_process_tree_view,
        ])
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                window.app_handle().exit(0);
            }
        })
        .build(tauri::generate_context!())
        .map_err(|err| format!("failed to build Tauri application: {err}"))?;

    app.run(|_app_handle, event| {
        if let tauri::RunEvent::ExitRequested { .. } = event {
            // Do not call `api.prevent_exit()`: closing the window must terminate
            // the UI process and WebView2 completely with 0 MB resident (`決定記録 L-08`).
        }
    });

    Ok(())
}

fn main() {
    let mode = match parse_launch_mode(std::env::args()) {
        Ok(mode) => mode,
        Err(err) => {
            eprintln!("ledr-ui argument error: {err}");
            std::process::exit(2);
        }
    };
    let ipc_client = IpcClient::default_endpoint();

    if matches!(mode, LaunchMode::RegisterUri) {
        if let Err(err) = dispatch_register_uri() {
            eprintln!("{err}");
            std::process::exit(1);
        }
        return;
    }

    if let LaunchMode::Notify(ref alert_id) = mode {
        if let Err(err) = dispatch_notify_oneshot(alert_id, &ipc_client) {
            eprintln!("{err}");
            std::process::exit(1);
        }
        return;
    }

    if let Err(err) = run_gui(mode, ipc_client) {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
