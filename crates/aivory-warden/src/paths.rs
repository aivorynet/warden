//! Paths of the config dir, the data dir and the IPC endpoint.

use std::path::{Path, PathBuf};
use warden_core::{Result, WardenError};

/// All paths that the binary uses.
///
/// The env var `WARDEN_HOME` moves everything below one directory. Tests use it.
#[derive(Debug, Clone)]
pub struct Paths {
    /// Config dir: settings, pairing store, tokens, device key.
    pub config: PathBuf,
    /// Data dir: journal, inbox, default vault.
    pub data: PathBuf,
    home: Option<PathBuf>,
}

impl Paths {
    /// Find the paths for the current user.
    pub fn discover() -> Result<Self> {
        if let Some(h) = std::env::var_os("WARDEN_HOME").filter(|h| !h.is_empty()) {
            return Ok(Self::from_home(PathBuf::from(h)));
        }
        let dirs = directories::ProjectDirs::from("net", "aivory", "Warden")
            .ok_or_else(|| WardenError::Config("cannot find the home directory".into()))?;
        Ok(Self {
            config: dirs.config_dir().to_path_buf(),
            data: dirs.data_dir().to_path_buf(),
            home: None,
        })
    }

    /// Put every path below `home`.
    pub fn from_home(home: PathBuf) -> Self {
        Self {
            config: home.join("config"),
            data: home.join("data"),
            home: Some(home),
        }
    }

    /// The settings file (settings, vault dir override, coffee state).
    pub fn settings_file(&self) -> PathBuf {
        self.config.join("settings.json")
    }

    /// The pairing store (token hashes only).
    pub fn pairing_file(&self) -> PathBuf {
        self.config.join("pairing.json")
    }

    /// Token file of the CLI.
    pub fn cli_token(&self) -> PathBuf {
        self.config.join("cli.token")
    }

    /// Token file of the native messaging host.
    pub fn native_host_token(&self) -> PathBuf {
        self.config.join("native-host.token")
    }

    /// Token file of the MCP server (written by `pair --save`).
    pub fn mcp_token(&self) -> PathBuf {
        self.config.join("mcp.token")
    }

    /// Local device state of the vault (device key, rollback marker).
    pub fn device_dir(&self) -> PathBuf {
        self.config.join("device")
    }

    /// Cache of the device id, so a locked daemon can report it.
    pub fn device_id_file(&self) -> PathBuf {
        self.config.join("device-id")
    }

    /// Marker file: the vault is soft locked (the key stays cached, but the daemon must not
    /// open the vault at start). Quick unlock removes it.
    pub fn soft_lock_file(&self) -> PathBuf {
        self.config.join("soft-locked")
    }

    /// Device-local audit log (one JSON line per entry). It holds events that are not item
    /// changes, for example a quick unlock.
    pub fn local_audit_file(&self) -> PathBuf {
        self.data.join("audit-local.jsonl")
    }

    /// Rotation journal.
    pub fn journal_dir(&self) -> PathBuf {
        self.data.join("journal")
    }

    /// Encrypted inbox.
    pub fn inbox_file(&self) -> PathBuf {
        self.data.join("inbox.json")
    }

    /// Default vault directory.
    pub fn default_vault(&self) -> PathBuf {
        self.data.join("vault")
    }

    /// The `WARDEN_HOME` directory, if one is set.
    pub fn home_override(&self) -> Option<&Path> {
        self.home.as_deref()
    }

    /// IPC endpoint. `None` selects the per-user default of `warden-ipc`.
    pub fn endpoint(&self) -> Option<PathBuf> {
        let home = self.home.as_ref()?;
        if cfg!(windows) {
            let h = blake3::hash(home.to_string_lossy().as_bytes()).to_hex();
            Some(PathBuf::from(format!(
                r"\\.\pipe\aivory-warden-home-{}",
                &h.as_str()[..16]
            )))
        } else {
            Some(home.join("run").join("w.sock"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_override_isolates_everything() {
        let p = Paths::from_home(PathBuf::from("/tmp/x"));
        assert!(p.settings_file().starts_with("/tmp/x"));
        assert!(p.default_vault().starts_with("/tmp/x"));
        assert!(p.endpoint().is_some());
    }
}
