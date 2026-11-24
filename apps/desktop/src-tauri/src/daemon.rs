//! The connection to the daemon, and the few actions that need the CLI binary.

use aivory_warden::{Paths, desktop};
use serde::Serialize;
use serde_json::Value;
use std::path::PathBuf;
use std::time::Duration;
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
    "inbox_list",
    "inbox_accept",
    "inbox_reject",
    "pair",
    "get_settings",
    "set_settings",
    "coffee_status",
    "coffee_receipt",
    "audit_list",
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
        for attempt in 0..2 {
            let parsed: Request = serde_json::from_value(req.clone()).map_err(|e| e.to_string())?;
            let mut guard = self.client.lock().await;
            if guard.is_none() {
                *guard = Some(self.connect().await?);
            }
            let Some(client) = guard.as_mut() else {
                return Err("daemon not reachable".into());
            };
            match client.call(parsed).await {
                Ok(resp) => return serde_json::to_value(&resp).map_err(|e| e.to_string()),
                Err(e) => {
                    *guard = None;
                    if attempt == 1 {
                        return Err(e.to_string());
                    }
                }
            }
        }
        Err("daemon not reachable".into())
    }

    pub fn sign_pledge(&self) -> Result<(), String> {
        desktop::sign_pledge(&self.paths).map_err(|e| e.to_string())
    }

    pub fn list_mcp_clients(&self) -> Result<Value, String> {
        let list = desktop::list_mcp_clients(&self.paths).map_err(|e| e.to_string())?;
        serde_json::to_value(list).map_err(|e| e.to_string())
    }

    pub fn unpair_mcp_client(&self, id: &str) -> Result<(), String> {
        desktop::unpair_mcp_client(&self.paths, id).map_err(|e| e.to_string())
    }

    /// Create the vault with `aivory-warden init`. The password goes in the child env only.
    pub async fn init_vault(&self, password: String, device_name: String) -> Result<Kit, String> {
        let mut cmd = cli_command();
        cmd.args(["init", "--pledge"]);
        if !device_name.trim().is_empty() {
            cmd.args(["--device-name", device_name.trim()]);
        }
        cmd.env("WARDEN_PASSWORD", password);
        let out = cmd.output().await.map_err(|e| e.to_string())?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            return Err(err.lines().last().unwrap_or("init failed").to_owned());
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let field = |label: &str| {
            text.lines()
                .find_map(|l| l.strip_prefix(label))
                .map(|v| v.trim().to_owned())
                .unwrap_or_default()
        };
        let kit = Kit {
            secret_key: field("Secret Key:"),
            vault: field("Vault:"),
            device: field("Device:"),
            ticket: field("Coffee ticket:"),
        };
        if kit.secret_key.is_empty() {
            return Err("init did not print a Secret Key".into());
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
