//! Aivory Warden desktop app. It is a front end to the background daemon and never holds
//! the vault. Every command goes through `warden_ipc::Client` with the own Full token.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod daemon;
mod tray;

use daemon::Daemon;
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;
use tauri::State;

type Shared<'a> = State<'a, Arc<Daemon>>;

/// What the UI needs to choose its first screen.
#[derive(Debug, Serialize)]
struct AppState {
    daemon_up: bool,
    vault_exists: bool,
    status: Option<Value>,
    error: Option<String>,
    /// Name of this computer, the default device name.
    computer_name: String,
}

fn computer_name() -> String {
    gethostname::gethostname()
        .to_string_lossy()
        .trim()
        .to_owned()
}

#[tauri::command]
async fn app_state(d: Shared<'_>) -> Result<AppState, String> {
    let vault_exists = d.vault_exists();
    match d.call(serde_json::json!({ "type": "status" })).await {
        Ok(status) => Ok(AppState {
            daemon_up: true,
            vault_exists,
            status: Some(status),
            error: None,
            computer_name: computer_name(),
        }),
        Err(e) => Ok(AppState {
            daemon_up: false,
            vault_exists,
            status: None,
            error: Some(e),
            computer_name: computer_name(),
        }),
    }
}

/// Forward one request to the daemon. Only a fixed list of request types passes.
#[tauri::command]
async fn daemon_call(d: Shared<'_>, request: Value) -> Result<Value, String> {
    d.call(request).await
}

#[tauri::command]
async fn sign_pledge(d: Shared<'_>) -> Result<(), String> {
    d.sign_pledge().await
}

#[tauri::command]
async fn init_vault(
    d: Shared<'_>,
    password: String,
    device_name: String,
) -> Result<daemon::Kit, String> {
    d.init_vault(password, device_name).await
}

#[tauri::command]
async fn start_service(d: Shared<'_>) -> Result<(), String> {
    d.start_service().await
}

#[tauri::command]
fn open_url(url: String) -> Result<(), String> {
    if !url.starts_with("https://") {
        return Err("only https links open".into());
    }
    open::that(url).map_err(|e| e.to_string())
}

/// The AI tools that Warden can connect, and their state.
#[tauri::command]
async fn mcp_setup_list() -> Result<Vec<Value>, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let env = aivory_warden::mcp_setup::Env::real().map_err(|e| e.to_string())?;
        Ok(aivory_warden::mcp_setup::list(&env)
            .into_iter()
            .map(|s| {
                serde_json::json!({
                    "id": s.id, "name": s.name, "installed": s.installed,
                    "connected": s.connected, "config": s.config.display().to_string(),
                })
            })
            .collect())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Connect the listed clients. One entry per client: `{id, ok, message}`.
#[tauri::command]
async fn mcp_setup_connect(ids: Vec<String>) -> Result<Vec<Value>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        use aivory_warden::mcp_setup as m;
        let env = m::Env::real().map_err(|e| e.to_string())?;
        let paths = aivory_warden::Paths::discover().map_err(|e| e.to_string())?;
        let bin = m::binary_path().map_err(|e| e.to_string())?;
        Ok(ids
            .iter()
            .map(|id| match m::add(&env, &paths, id, &bin) {
                Ok(o) => serde_json::json!({
                    "id": id, "ok": true,
                    "message": if o == m::Outcome::AlreadyConnected { "already connected" } else { "connected" },
                }),
                Err(e) => serde_json::json!({ "id": id, "ok": false, "message": e.to_string() }),
            })
            .collect())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Remove the Warden entry from one client and unpair it.
#[tauri::command]
async fn mcp_setup_remove(id: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let env = aivory_warden::mcp_setup::Env::real().map_err(|e| e.to_string())?;
        let paths = aivory_warden::Paths::discover().map_err(|e| e.to_string())?;
        aivory_warden::mcp_setup::remove(&env, &paths, &id)
            .map(|_| ())
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

fn main() {
    let daemon = match Daemon::discover() {
        Ok(d) => Arc::new(d),
        Err(e) => {
            eprintln!("aivory-warden-desktop: {e}");
            std::process::exit(1);
        }
    };
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            tray::show_main(app);
        }))
        .manage(daemon)
        .invoke_handler(tauri::generate_handler![
            app_state,
            daemon_call,
            sign_pledge,
            init_vault,
            start_service,
            open_url,
            mcp_setup_list,
            mcp_setup_connect,
            mcp_setup_remove
        ])
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .setup(|app| {
            tray::build(app.handle())?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .unwrap_or_else(|e| {
            eprintln!("aivory-warden-desktop: {e}");
            std::process::exit(1);
        });
}
