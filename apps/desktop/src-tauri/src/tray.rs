//! The tray icon: Open, Rotate due tokens, Inbox, Settings, Lock now, Quit app.

use crate::daemon::Daemon;
use std::sync::Arc;
use std::time::Duration;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager};

/// Show and focus the main window.
pub fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

/// Show or hide the tray icon.
pub fn set_visible(app: &AppHandle, on: bool) {
    if let Some(t) = app.tray_by_id("main") {
        let _ = t.set_visible(on);
    }
}

/// Build the tray and start the refresh task.
pub fn build(app: &AppHandle) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Open Warden", true, None::<&str>)?;
    let rotate = MenuItem::with_id(app, "rotate", "Rotate due tokens", true, None::<&str>)?;
    let inbox = MenuItem::with_id(app, "inbox", "Inbox", true, None::<&str>)?;
    let settings = MenuItem::with_id(app, "settings", "Settings", true, None::<&str>)?;
    let lock = MenuItem::with_id(app, "lock", "Lock now", true, None::<&str>)?;
    let quit = MenuItem::with_id(
        app,
        "quit",
        "Quit app (rotation keeps running)",
        true,
        None::<&str>,
    )?;
    let sep = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(
        app,
        &[&open, &rotate, &inbox, &settings, &lock, &sep, &quit],
    )?;
    let mut builder = TrayIconBuilder::with_id("main")
        .tooltip("Aivory Warden")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_tray_icon_event(|tray, event| {
            if let tauri::tray::TrayIconEvent::Click {
                button: tauri::tray::MouseButton::Left,
                button_state: tauri::tray::MouseButtonState::Up,
                ..
            } = event
            {
                show_main(tray.app_handle());
            }
        })
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => show_main(app),
            "inbox" => {
                show_main(app);
                let _ = app.emit("navigate", "inbox");
            }
            "settings" => {
                show_main(app);
                let _ = app.emit("navigate", "settings");
            }
            "rotate" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let d = app.state::<Arc<Daemon>>().inner().clone();
                    rotate_due(&d).await;
                    let _ = app.emit("state-changed", ());
                });
            }
            "lock" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let d = app.state::<Arc<Daemon>>().inner().clone();
                    let _ = d.call(serde_json::json!({ "type": "lock" })).await;
                    let _ = app.emit("state-changed", ());
                });
            }
            "quit" => app.exit(0),
            _ => {}
        });
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app)?;

    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            let d = app.state::<Arc<Daemon>>().inner().clone();
            let due = due_ids(&d).await.len();
            let count = match d.call(serde_json::json!({ "type": "status" })).await {
                Ok(s) => s["inbox_count"].as_u64().unwrap_or(0),
                Err(_) => 0,
            };
            let _ = rotate.set_text(if due > 0 {
                format!("Rotate due tokens ({due} due)")
            } else {
                "Rotate due tokens".to_owned()
            });
            let _ = inbox.set_text(format!("Inbox ({count} captured)"));
            tokio::time::sleep(Duration::from_secs(20)).await;
        }
    });
    Ok(())
}

/// Ids of the items that are due now (auto-rotate on, next rotation in the past).
async fn due_ids(d: &Daemon) -> Vec<String> {
    let Ok(v) = d.call(serde_json::json!({ "type": "list_items" })).await else {
        return Vec::new();
    };
    let now = chrono::Utc::now();
    v["items"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|i| i["auto_rotate"] == true && i["provider"] != "manual")
        .filter(|i| {
            i["next_rotation"]
                .as_str()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .is_some_and(|t| t <= now)
        })
        .filter_map(|i| i["id"].as_str().map(str::to_owned))
        .collect()
}

async fn rotate_due(d: &Daemon) {
    for id in due_ids(d).await {
        let _ = d
            .call(serde_json::json!({ "type": "rotate_now", "item": id }))
            .await;
    }
}
