//! Helpers that the desktop app needs before it can talk to the daemon: its own Full token
//! and the vault check. Every other action goes through IPC.

use crate::paths::Paths;
use crate::store::{self, PairingFile};
use warden_core::Result;
use warden_core::ipc::Capability;

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
