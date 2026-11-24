//! Helpers that the desktop app shares with the CLI: its own Full token, the coffee pledge
//! and the list of paired MCP clients.

use crate::paths::Paths;
use crate::store::{self, PairingFile};
use serde::Serialize;
use warden_coffee::CoffeeStore;
use warden_core::ipc::Capability;
use warden_core::{Result, SystemClock, WardenError};

/// Return the token of the desktop app. Create and pair it with `Full` when it is missing.
pub fn desktop_token(paths: &Paths) -> Result<String> {
    std::fs::create_dir_all(&paths.config)?;
    let file = paths.config.join("desktop.token");
    let pairing = PairingFile::new(paths.pairing_file());
    if !pairing.token_file_valid(&file) {
        let t = pairing.add("desktop", &[Capability::Full])?;
        store::write_token(&file, &t)?;
    }
    store::read_token(&file)
}

/// Return true when a vault header exists in the vault directory.
pub fn vault_exists(paths: &Paths) -> bool {
    store::vault_dir(paths).is_ok_and(|d| d.join("header.json").exists())
}

/// Record the signed coffee pledge in the settings file.
pub fn sign_pledge(paths: &Paths) -> Result<()> {
    std::fs::create_dir_all(&paths.config)?;
    let store = CoffeeStore::new(paths.settings_file());
    let mut st = store
        .load()
        .map_err(|e| WardenError::Config(e.to_string()))?;
    if warden_coffee::is_pledged(&st) {
        return Ok(());
    }
    let user = ["USERNAME", "USER"]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
        .unwrap_or_else(|| "unknown".into());
    warden_coffee::sign_pledge(&mut st, &user, &SystemClock);
    store
        .save(&st)
        .map_err(|e| WardenError::Config(e.to_string()))
}

/// A paired MCP client, without its token or hash.
#[derive(Debug, Clone, Serialize)]
pub struct PairedMcpClient {
    /// Short id for `unpair_client`.
    pub id: String,
    /// Client name.
    pub name: String,
    /// Capabilities.
    pub caps: Vec<Capability>,
    /// Pairing time (RFC 3339).
    pub created_at: String,
}

fn is_mcp(v: &serde_json::Value) -> bool {
    v.get("caps")
        .and_then(|c| c.as_array())
        .is_some_and(|c| c.iter().any(|x| x == "mcp_use" || x == "mcp_admin"))
}

fn load_doc(paths: &Paths) -> Result<serde_json::Value> {
    match std::fs::read(paths.pairing_file()) {
        Ok(b) => Ok(serde_json::from_slice(&b)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok(serde_json::json!({ "clients": [] }))
        }
        Err(e) => Err(e.into()),
    }
}

/// List the paired MCP clients.
pub fn list_mcp_clients(paths: &Paths) -> Result<Vec<PairedMcpClient>> {
    let doc = load_doc(paths)?;
    let mut out = Vec::new();
    for c in doc["clients"].as_array().into_iter().flatten() {
        if !is_mcp(c) {
            continue;
        }
        out.push(PairedMcpClient {
            id: c["hash"]
                .as_str()
                .unwrap_or_default()
                .chars()
                .take(12)
                .collect(),
            name: c["name"].as_str().unwrap_or_default().to_owned(),
            caps: serde_json::from_value(c["caps"].clone()).unwrap_or_default(),
            created_at: c["created_at"].as_str().unwrap_or_default().to_owned(),
        });
    }
    Ok(out)
}

/// Remove one paired MCP client. Other clients (CLI, desktop, native host) stay.
pub fn unpair_mcp_client(paths: &Paths, id: &str) -> Result<()> {
    if id.len() < 8 {
        return Err(WardenError::Config("client id too short".into()));
    }
    let mut doc = load_doc(paths)?;
    if let Some(list) = doc["clients"].as_array_mut() {
        list.retain(|c| !(is_mcp(c) && c["hash"].as_str().is_some_and(|h| h.starts_with(id))));
    }
    let file = paths.pairing_file();
    let tmp = file.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&doc)?)?;
    std::fs::rename(&tmp, &file)?;
    Ok(())
}
