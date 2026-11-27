//! Aivory Warden desktop app. It is a front end to the background daemon and never holds
//! the vault. Every command goes through `warden_ipc::Client` with the own Full token.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod daemon;
mod prefs;
mod tray;

use daemon::Daemon;
use prefs::Prefs;
use serde::Serialize;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Manager, State};
use tauri_plugin_autostart::ManagerExt;

type Shared<'a> = State<'a, Arc<Daemon>>;

/// The app preferences and the file that holds them.
struct PrefStore {
    path: PathBuf,
    prefs: Mutex<Prefs>,
}

impl PrefStore {
    fn get(&self) -> Prefs {
        self.prefs.lock().map(|p| p.clone()).unwrap_or_default()
    }
}

/// The App section of Settings: the preferences plus the two login entries, read from the OS.
#[derive(Debug, Serialize)]
struct AppPrefs {
    #[serde(flatten)]
    prefs: Prefs,
    /// The OS opens the desktop app at login.
    open_at_login: bool,
    /// The background service (rotation) starts at login.
    service_installed: bool,
}

#[tauri::command]
async fn app_prefs(
    app: AppHandle,
    store: State<'_, PrefStore>,
    d: Shared<'_>,
) -> Result<AppPrefs, String> {
    Ok(AppPrefs {
        prefs: store.get(),
        open_at_login: match packaged_alias() {
            Some(_) => login_entry_exists(),
            None => app.autolaunch().is_enabled().unwrap_or(false),
        },
        service_installed: d.service_installed().await.unwrap_or(false),
    })
}

/// Save the preferences and apply them at once (tray icon visible or not).
#[tauri::command]
fn set_app_prefs(app: AppHandle, store: State<'_, PrefStore>, prefs: Prefs) -> Result<(), String> {
    prefs.save(&store.path)?;
    tray::set_visible(&app, prefs.show_tray);
    if let Ok(mut p) = store.prefs.lock() {
        *p = prefs;
    }
    Ok(())
}

/// Add or remove the login entry of the desktop app. It starts the app with `--hidden`.
#[tauri::command]
fn set_open_at_login(app: AppHandle, on: bool) -> Result<(), String> {
    if let Some(alias) = packaged_alias() {
        return set_login_entry(on.then_some(alias.as_path()));
    }
    let l = app.autolaunch();
    if on { l.enable() } else { l.disable() }.map_err(|e| e.to_string())
}

/// Name of the login entry of the desktop app (the daemon uses `AivoryWarden`).
const LOGIN_ENTRY: &str = "Aivory Warden";
const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";

/// The app alias of the CLI when the desktop app runs from the Store package. The package
/// path changes with each update, and only the CLI has an alias, so the login entry runs
/// `aivory-warden open-app --hidden`.
fn packaged_alias() -> Option<PathBuf> {
    let cli = std::env::current_exe()
        .ok()?
        .with_file_name("aivory-warden.exe");
    let local = std::env::var_os("LOCALAPPDATA")?;
    aivory_warden::packaged::alias_for(&cli, std::path::Path::new(&local))
}

fn reg(args: &[&str]) -> Result<std::process::Output, String> {
    let mut c = std::process::Command::new("reg");
    c.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000);
    }
    c.output().map_err(|e| e.to_string())
}

fn login_entry_exists() -> bool {
    reg(&["query", RUN_KEY, "/v", LOGIN_ENTRY]).is_ok_and(|o| o.status.success())
}

/// Write (`Some(alias)`) or remove (`None`) the login entry. It starts the app in the tray.
fn set_login_entry(alias: Option<&std::path::Path>) -> Result<(), String> {
    let out = match alias {
        Some(a) => {
            let cmd = format!("\"{}\" open-app {}", a.display(), prefs::HIDDEN_FLAG);
            reg(&[
                "add",
                RUN_KEY,
                "/v",
                LOGIN_ENTRY,
                "/t",
                "REG_SZ",
                "/d",
                &cmd,
                "/f",
            ])?
        }
        None if !login_entry_exists() => return Ok(()),
        None => reg(&["delete", RUN_KEY, "/v", LOGIN_ENTRY, "/f"])?,
    };
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_owned())
    }
}

/// Remove the background service. Rotation stops until the service runs again.
#[tauri::command]
async fn remove_service(d: Shared<'_>) -> Result<(), String> {
    d.remove_service().await
}

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

/// Whether the OS user check exists on this device, and its name for the button.
#[derive(Debug, Serialize)]
struct QuickInfo {
    available: bool,
    label: &'static str,
}

#[tauri::command]
async fn quick_unlock_info() -> Result<QuickInfo, String> {
    tokio::task::spawn_blocking(|| {
        let v = warden_verify::platform();
        QuickInfo {
            available: v.available(),
            label: v.label(),
        }
    })
    .await
    .map_err(|e| e.to_string())
}

/// Run the OS user check on the main window, then ask the daemon for a quick unlock.
#[tauri::command]
async fn quick_unlock(d: Shared<'_>, window: tauri::WebviewWindow) -> Result<Value, String> {
    #[cfg(windows)]
    let hwnd = window.hwnd().ok().map(|h| h.0 as isize);
    #[cfg(not(windows))]
    let hwnd = {
        let _ = &window;
        None
    };
    d.quick_unlock(hwnd).await
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
async fn run_daemon(d: Shared<'_>) -> Result<(), String> {
    d.run_daemon().await
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
    let store = match aivory_warden::Paths::discover() {
        Ok(p) => {
            let path = prefs::path(&p.config);
            PrefStore {
                prefs: Mutex::new(Prefs::load(&path)),
                path,
            }
        }
        Err(e) => {
            eprintln!("aivory-warden-desktop: {e}");
            std::process::exit(1);
        }
    };
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            tray::show_main(app);
        }))
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec![prefs::HIDDEN_FLAG]),
        ))
        .manage(daemon)
        .manage(store)
        .invoke_handler(tauri::generate_handler![
            app_state,
            daemon_call,
            quick_unlock_info,
            quick_unlock,
            sign_pledge,
            init_vault,
            start_service,
            run_daemon,
            remove_service,
            app_prefs,
            set_app_prefs,
            set_open_at_login,
            open_url,
            mcp_setup_list,
            mcp_setup_connect,
            mcp_setup_remove
        ])
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let app = window.app_handle();
                if app.state::<PrefStore>().get().hide_on_close() {
                    api.prevent_close();
                    let _ = window.hide();
                } else {
                    // Without a tray the app quits. The daemon keeps running.
                    app.exit(0);
                }
            }
        })
        .setup(|app| {
            let p = app.state::<PrefStore>().get();
            tray::build(app.handle())?;
            tray::set_visible(app.handle(), p.show_tray);
            let args: Vec<String> = std::env::args().collect();
            if !p.start_in_tray(&args) {
                tray::show_main(app.handle());
            }
            // The browser extension works without a terminal step: register its native host
            // on every start. This also fixes the host path after an update.
            let d = app.state::<Arc<Daemon>>().inner().clone();
            tauri::async_runtime::spawn(async move {
                if let Err(e) = d.register_extension().await {
                    eprintln!("aivory-warden-desktop: browser extension not registered: {e}");
                }
            });
            Ok(())
        })
        .run(tauri::generate_context!())
        .unwrap_or_else(|e| {
            eprintln!("aivory-warden-desktop: {e}");
            std::process::exit(1);
        });
}
