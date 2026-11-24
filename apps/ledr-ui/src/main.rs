#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod cli;
mod commands;
mod defense_status;
mod ipc;
mod notify;
#[cfg(test)]
mod tests;
mod tree;
mod updater;
mod uri_reg;

pub use cli::LaunchMode;
pub use notify::DISABLE_OS_TOAST_ENV;

use cli::{CliAction, parse_cli_action};
use ipc::IpcClient;
use notify::dispatch_notify_oneshot;
use tauri::Manager;
use updater::{AppUpdateManager, UpdaterConfig, dispatch_apply_verified_update};
use uri_reg::dispatch_register_uri;

fn run_gui(launch_mode: LaunchMode, ipc_client: IpcClient) -> Result<(), String> {
    let app = tauri::Builder::default()
        .manage(launch_mode)
        .manage(ipc_client)
        .setup(|app| {
            let mgr = AppUpdateManager::new(UpdaterConfig::production(app.handle().clone()));
            let gc_mgr = mgr.clone();
            tauri::async_runtime::spawn_blocking(move || {
                if let Err(err) = gc_mgr.run_startup_gc_sync() {
                    eprintln!("updater: startup staging GC warning: {err}");
                }
            });
            app.manage(mgr);
            Ok(())
        })
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
            commands::get_updater_status,
            commands::check_for_updates,
            commands::apply_update,
            commands::cancel_update_download,
            commands::trigger_startup_update_check,
            commands::open_release_notes_url,
        ])
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                if let Some(mgr) = window.try_state::<AppUpdateManager>() {
                    mgr.cancel_and_cleanup_on_close();
                }
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
    let action = match parse_cli_action(std::env::args()) {
        Ok(action) => action,
        Err(err) => {
            eprintln!("ledr-ui argument error: {err}");
            std::process::exit(2);
        }
    };

    let mode = match action {
        CliAction::ApplyVerifiedUpdate(ref args) => {
            let code = dispatch_apply_verified_update(args);
            if code != 0 {
                std::process::exit(code);
            }
            return;
        }
        CliAction::Launch(mode) => mode,
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
