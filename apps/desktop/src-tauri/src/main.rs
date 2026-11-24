//! Aivory Warden desktop app. It is a front end to the background daemon and never holds
//! the vault. Every command goes through `warden_ipc::Client` with the own Full token.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod daemon;
mod tray;

use daemon::Daemon;
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Manager, State};

type Shared<'a> = State<'a, Arc<Daemon>>;

/// What the UI needs to choose its first screen.
#[derive(Debug, Serialize)]
struct AppState {
    daemon_up: bool,
    vault_exists: bool,
    status: Option<Value>,
    error: Option<String>,
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
        }),
        Err(e) => Ok(AppState {
            daemon_up: false,
            vault_exists,
            status: None,
            error: Some(e),
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

/// Apply a receipt code from a deep link and tell the UI.
async fn apply_receipt(app: AppHandle, d: Arc<Daemon>, code: String) {
    let result = d
        .call(serde_json::json!({ "type": "coffee_receipt", "code": code }))
        .await;
    let ok = matches!(&result, Ok(v) if v["type"] != "error");
    let message = match result {
        Ok(v) if v["type"] == "error" => v["message"].as_str().unwrap_or("rejected").to_owned(),
        Ok(_) => "Receipt applied. Thank you for the coffee.".to_owned(),
        Err(e) => e,
    };
    tray::show_main(&app);
    let _ = app.emit(
        "receipt-result",
        serde_json::json!({ "ok": ok, "message": message }),
    );
}

fn receipt_code(url: &str) -> Option<String> {
    let rest = url.strip_prefix("aivory-warden://receipt/")?;
    let code = rest.trim_matches('/');
    (!code.is_empty() && code.len() < 4096).then(|| code.to_owned())
}

fn handle_urls(app: &AppHandle, urls: impl IntoIterator<Item = String>) {
    for u in urls {
        if let Some(code) = receipt_code(&u) {
            let d = app.state::<Arc<Daemon>>().inner().clone();
            tauri::async_runtime::spawn(apply_receipt(app.clone(), d, code));
        }
    }
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
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            tray::show_main(app);
            handle_urls(app, argv);
        }))
        .plugin(tauri_plugin_deep_link::init())
        .manage(daemon)
        .invoke_handler(tauri::generate_handler![
            app_state,
            daemon_call,
            sign_pledge,
            init_vault,
            start_service,
            open_url
        ])
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .setup(|app| {
            use tauri_plugin_deep_link::DeepLinkExt;
            #[cfg(any(windows, target_os = "linux"))]
            let _ = app.deep_link().register_all();
            let handle = app.handle().clone();
            app.deep_link().on_open_url(move |event| {
                handle_urls(&handle, event.urls().into_iter().map(|u| u.to_string()));
            });
            if let Ok(Some(urls)) = app.deep_link().get_current() {
                handle_urls(app.handle(), urls.into_iter().map(|u| u.to_string()));
            }
            tray::build(app.handle())?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .unwrap_or_else(|e| {
            eprintln!("aivory-warden-desktop: {e}");
            std::process::exit(1);
        });
}

#[cfg(test)]
mod tests {
    use super::receipt_code;

    #[test]
    fn receipt_link_parses() {
        assert_eq!(
            receipt_code("aivory-warden://receipt/abc-123").as_deref(),
            Some("abc-123")
        );
        assert_eq!(receipt_code("aivory-warden://receipt/"), None);
        assert_eq!(receipt_code("https://x/receipt/abc"), None);
    }
}
