//! The connection to the daemon, and the few actions that need the CLI binary.

use aivory_warden::{Paths, desktop};
use serde::Serialize;
use serde_json::Value;
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use warden_core::ipc::Request;
use warden_ipc::Client;

/// Request types that the UI may send. `inbox_add` and `mcp_http_request` are not on the list.
const ALLOWED: &[&str] = &[
    "status",
    "list_items",
    "get_item",
    "add_item",
    "update_policy",
    "rotate_now",
    "delete_item",
    "unlock",
    "lock",
    "lock_forget",
    "inbox_list",
    "inbox_accept",
    "inbox_reject",
    "pair",
    "get_settings",
    "set_settings",
    "coffee_status",
    "coffee_mark_paid",
    "audit_list",
    "sign_pledge",
    "list_clients",
    "unpair",
    "list_devices",
    "update_item",
];

/// The Emergency Kit data that `init` prints. The Secret Key is shown once.
#[derive(Debug, Serialize)]
pub struct Kit {
    pub secret_key: String,
    pub vault: String,
    pub device: String,
    pub ticket: String,
}

/// Shared state of the app.
#[derive(Debug)]
pub struct Daemon {
    paths: Paths,
    client: Mutex<Option<Client>>,
}

impl Daemon {
    pub fn discover() -> Result<Self, String> {
        Ok(Self {
            paths: Paths::discover().map_err(|e| e.to_string())?,
            client: Mutex::new(None),
        })
    }

    pub fn vault_exists(&self) -> bool {
        desktop::vault_exists(&self.paths)
    }

    async fn connect(&self) -> Result<Client, String> {
        let token = desktop::desktop_token(&self.paths).map_err(|e| e.to_string())?;
        Client::connect(self.paths.endpoint().as_deref(), Some(&token))
            .await
            .map_err(|e| format!("daemon not reachable: {e}"))
    }

    /// Send one request. A broken connection is rebuilt once.
    pub async fn call(&self, req: Value) -> Result<Value, String> {
        let kind = req["type"].as_str().unwrap_or_default();
        if !ALLOWED.contains(&kind) {
            return Err(format!("request `{kind}` is not allowed"));
        }
        self.send(req).await
    }

    /// Run the OS user check, then send `UnlockQuick`. The webview cannot send `unlock_quick`
    /// itself (it is not on the allow list), so it cannot skip the check. `hwnd` is the native
    /// window handle of the main window.
    pub async fn quick_unlock(&self, hwnd: Option<isize>) -> Result<Value, String> {
        let verifier = warden_verify::platform();
        tokio::task::spawn_blocking(move || verifier.verify(hwnd, "Unlock Aivory Warden"))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
        self.send(serde_json::json!({ "type": "unlock_quick" }))
            .await
    }

    async fn send(&self, req: Value) -> Result<Value, String> {
        for attempt in 0..2 {
            let parsed: Request = serde_json::from_value(req.clone()).map_err(|e| e.to_string())?;
            // Take the connection out of the slot. The lock is free during the call, so a slow
            // answer does not block another request. A parallel request opens its own connection.
            let cached = self.client.lock().await.take();
            let reused = cached.is_some();
            let mut client = match cached {
                Some(c) => c,
                None => self.connect().await?,
            };
            match client.call(parsed).await {
                Ok(resp) => {
                    if !client.is_broken() {
                        let mut slot = self.client.lock().await;
                        if slot.is_none() {
                            *slot = Some(client);
                        }
                    }
                    return serde_json::to_value(&resp).map_err(|e| e.to_string());
                }
                Err(e) => {
                    // Only a stale cached connection earns a second try.
                    if !reused || attempt == 1 {
                        return Err(e.to_string());
                    }
                }
            }
        }
        Err("daemon not reachable".into())
    }

    /// Sign the coffee pledge in the daemon, in the name of the OS user.
    pub async fn sign_pledge(&self) -> Result<(), String> {
        let user = ["USERNAME", "USER"]
            .iter()
            .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
            .unwrap_or_else(|| "unknown".into());
        let resp = self
            .call(serde_json::json!({ "type": "sign_pledge", "user": user }))
            .await?;
        if resp["type"] == "error" {
            return Err(resp["message"].as_str().unwrap_or("rejected").to_owned());
        }
        Ok(())
    }

    /// Create the vault with `aivory-warden init`. The password goes to the child on stdin.
    pub async fn init_vault(&self, password: String, device_name: String) -> Result<Kit, String> {
        let mut cmd = cli_command();
        cmd.args(["init", "--pledge", "--password-stdin", "--json"]);
        if !device_name.trim().is_empty() {
            cmd.args(["--device-name", device_name.trim()]);
        }
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = cmd.spawn().map_err(|e| e.to_string())?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(
                    format!(
                        "{password}
"
                    )
                    .as_bytes(),
                )
                .await
                .map_err(|e| e.to_string())?;
        }
        let out = child.wait_with_output().await.map_err(|e| e.to_string())?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            return Err(err.lines().last().unwrap_or("init failed").to_owned());
        }
        let v: Value = serde_json::from_slice(&out.stdout)
            .map_err(|_| "init returned no readable result".to_owned())?;
        let field = |k: &str| v[k].as_str().unwrap_or_default().to_owned();
        let kit = Kit {
            secret_key: field("secret_key"),
            vault: field("vault"),
            device: field("device"),
            ticket: field("ticket"),
        };
        if kit.secret_key.is_empty() {
            return Err("init did not return a Secret Key".into());
        }
        *self.client.lock().await = None;
        Ok(kit)
    }

    /// Run `aivory-warden service install`, then wait for the daemon.
    pub async fn start_service(&self) -> Result<(), String> {
        let out = cli_command()
            .args(["service", "install"])
            .output()
            .await
            .map_err(|e| e.to_string())?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            return Err(err
                .lines()
                .last()
                .unwrap_or("service install failed")
                .to_owned());
        }
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if self
                .call(serde_json::json!({ "type": "status" }))
                .await
                .is_ok()
            {
                return Ok(());
            }
        }
        Err("the service started, but the daemon does not answer yet".into())
    }

    /// Start `aivory-warden daemon` as a detached process, then wait for it. Unlike
    /// [`Self::start_service`] this adds no login entry, so it keeps the user's choice in
    /// Settings > App.
    pub async fn run_daemon(&self) -> Result<(), String> {
        let mut cmd = std::process::Command::new(cli_binary());
        cmd.arg("daemon")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        // DETACHED_PROCESS | CREATE_NO_WINDOW: the daemon outlives the app and shows no console.
        #[cfg(windows)]
        std::os::windows::process::CommandExt::creation_flags(&mut cmd, 0x0000_0008 | 0x0800_0000);
        cmd.spawn().map_err(|e| e.to_string())?;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if self
                .call(serde_json::json!({ "type": "status" }))
                .await
                .is_ok()
            {
                return Ok(());
            }
        }
        Err("the daemon started, but it does not answer yet".into())
    }

    /// Register the native messaging host of the "Save to Warden" browser extension
    /// (`aivory-warden extension install`). The command is idempotent, and it rewrites the host
    /// path after an update.
    pub async fn register_extension(&self) -> Result<(), String> {
        let out = cli_command()
            .args(["extension", "install"])
            .output()
            .await
            .map_err(|e| e.to_string())?;
        if out.status.success() {
            return Ok(());
        }
        let err = String::from_utf8_lossy(&out.stderr);
        Err(err
            .lines()
            .last()
            .unwrap_or("extension install failed")
            .to_owned())
    }

    /// Return true when the background service is installed (it starts at login).
    pub async fn service_installed(&self) -> Result<bool, String> {
        let out = cli_command()
            .args(["service", "status"])
            .output()
            .await
            .map_err(|e| e.to_string())?;
        Ok(out.status.success())
    }

    /// Remove the background service. This also stops the running daemon.
    pub async fn remove_service(&self) -> Result<(), String> {
        let out = cli_command()
            .args(["service", "uninstall"])
            .output()
            .await
            .map_err(|e| e.to_string())?;
        if out.status.success() {
            *self.client.lock().await = None;
            return Ok(());
        }
        let err = String::from_utf8_lossy(&out.stderr);
        Err(err
            .lines()
            .last()
            .unwrap_or("service uninstall failed")
            .to_owned())
    }
}

fn cli_binary() -> PathBuf {
    if let Some(p) = std::env::var_os("AIVORY_WARDEN_BIN") {
        return PathBuf::from(p);
    }
    let name = if cfg!(windows) {
        "aivory-warden.exe"
    } else {
        "aivory-warden"
    };
    std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.join(name)))
        .filter(|p| p.exists())
        .unwrap_or_else(|| PathBuf::from(name))
}

fn cli_command() -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(cli_binary());
    cmd.stdin(std::process::Stdio::null());
    #[cfg(windows)]
    cmd.creation_flags(0x0800_0000);
    cmd
}
