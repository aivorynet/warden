//! Cache of the vault key: OS keychain by default, 0600 key file as explicit opt-in.

use crate::crypto::{Hex, hex_enc, verr};
use crate::fsutil::atomic_write;
use std::path::{Path, PathBuf};
use warden_core::{Result, VaultId, WardenError};
use zeroize::Zeroizing;

const SERVICE: &str = "aivory-warden";

fn entry(vault_id: &VaultId) -> Result<keyring::Entry> {
    keyring::Entry::new(SERVICE, &vault_id.to_string()).map_err(|e| verr(format!("keychain: {e}")))
}

/// Store the vault key in the OS keychain.
pub fn store(vault_id: &VaultId, key: &[u8; 32]) -> Result<()> {
    entry(vault_id)?
        .set_secret(key)
        .map_err(|e| verr(format!("keychain store failed: {e}")))
}

/// Load the vault key from the OS keychain. Returns `None` when no key is cached.
pub fn load(vault_id: &VaultId) -> Result<Option<Zeroizing<[u8; 32]>>> {
    match entry(vault_id)?.get_secret() {
        Ok(b) => {
            let b = Zeroizing::new(b);
            let arr: [u8; 32] = b
                .as_slice()
                .try_into()
                .map_err(|_| verr("keychain entry has a bad length"))?;
            Ok(Some(Zeroizing::new(arr)))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(verr(format!("keychain load failed: {e}"))),
    }
}

/// Remove the cached vault key from the OS keychain. No error when none exists.
pub fn clear(vault_id: &VaultId) -> Result<()> {
    match entry(vault_id)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(verr(format!("keychain clear failed: {e}"))),
    }
}

/// A vault key cache in a file with mode 0600 (Unix). For headless Linux.
/// The caller must opt in explicitly. On Windows the file inherits the folder ACL.
#[derive(Debug, Clone)]
pub struct KeyFileCache {
    path: PathBuf,
}

impl KeyFileCache {
    /// Create a cache that uses `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Path of the key file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write the vault key (atomic, 0600).
    pub fn store(&self, key: &[u8; 32]) -> Result<()> {
        let text = Zeroizing::new(hex_enc(key));
        atomic_write(&self.path, text.as_bytes(), true)?;
        Ok(())
    }

    /// Read the vault key. Returns `None` when the file does not exist.
    pub fn load(&self) -> Result<Option<Zeroizing<[u8; 32]>>> {
        let raw = match std::fs::read_to_string(&self.path) {
            Ok(s) => Zeroizing::new(s),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(WardenError::Io(e)),
        };
        let h: Hex = serde_json::from_value(serde_json::Value::String(raw.trim().to_owned()))
            .map_err(|_| verr("key file is not valid hex"))?;
        Ok(Some(Zeroizing::new(h.arr()?)))
    }

    /// Delete the key file. No error when none exists.
    pub fn clear(&self) -> Result<()> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_file_roundtrip() {
        let d = tempfile::tempdir().unwrap();
        let c = KeyFileCache::new(d.path().join("sub").join("key"));
        assert!(c.load().unwrap().is_none());
        c.store(&[7u8; 32]).unwrap();
        assert_eq!(*c.load().unwrap().unwrap(), [7u8; 32]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(c.path()).unwrap().permissions().mode();
            assert_eq!(m & 0o777, 0o600);
        }
        c.clear().unwrap();
        assert!(c.load().unwrap().is_none());
    }

    /// Touches the real OS keychain. Run with `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn os_keychain_roundtrip() {
        let id = VaultId::new();
        assert!(load(&id).unwrap().is_none());
        store(&id, &[9u8; 32]).unwrap();
        assert_eq!(*load(&id).unwrap().unwrap(), [9u8; 32]);
        clear(&id).unwrap();
        assert!(load(&id).unwrap().is_none());
    }
}
