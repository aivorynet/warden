//! Local file stores: settings, pairing tokens (hashed) and the encrypted inbox.

use crate::paths::Paths;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use warden_core::ipc::{Capability, ClientInfo, InboxEntry};
use warden_core::{ClientToken, InboxId, Result, SecretValue, Settings, WardenError};
use warden_ipc::PairingStore;
use warden_vault::fsutil::atomic_write;

fn read_map(path: &Path) -> Result<serde_json::Map<String, serde_json::Value>> {
    match std::fs::read(path) {
        Ok(b) => match serde_json::from_slice(&b)? {
            serde_json::Value::Object(m) => Ok(m),
            _ => Err(WardenError::Config(format!(
                "{} is not a JSON object",
                path.display()
            ))),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Default::default()),
        Err(e) => Err(e.into()),
    }
}

fn update_settings_file(
    paths: &Paths,
    f: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>),
) -> Result<()> {
    let file = paths.settings_file();
    let mut m = read_map(&file)?;
    f(&mut m);
    atomic_write(&file, &serde_json::to_vec_pretty(&m)?, false)?;
    Ok(())
}

/// Load the global settings. A missing file gives the defaults.
pub fn load_settings(paths: &Paths) -> Result<Settings> {
    match read_map(&paths.settings_file())?.remove("settings") {
        Some(v) => Ok(serde_json::from_value(v)?),
        None => Ok(Settings::default()),
    }
}

/// Save the global settings. Other keys of the file stay.
pub fn save_settings(paths: &Paths, s: &Settings) -> Result<()> {
    let v = serde_json::to_value(s)?;
    update_settings_file(paths, |m| {
        m.insert("settings".into(), v);
    })
}

/// The vault directory: the setting `vault_dir`, or the default below the data dir.
pub fn vault_dir(paths: &Paths) -> Result<PathBuf> {
    Ok(read_map(&paths.settings_file())?
        .get("vault_dir")
        .and_then(|v| v.as_str())
        .map_or_else(|| paths.default_vault(), PathBuf::from))
}

/// Remember a vault directory (for example a synced folder).
pub fn set_vault_dir(paths: &Paths, dir: &Path) -> Result<()> {
    let s = dir.to_string_lossy().into_owned();
    update_settings_file(paths, |m| {
        m.insert("vault_dir".into(), s.into());
    })
}

/// Read a token file. Surrounding white space is removed.
pub fn read_token(path: &Path) -> Result<String> {
    Ok(std::fs::read_to_string(path)
        .map_err(|e| WardenError::Config(format!("cannot read token file: {e}")))?
        .trim()
        .to_owned())
}

/// Write a token file. The file is owner-only: mode 0600 on Unix, an owner-only DACL on Windows.
pub fn write_token(path: &Path, token: &ClientToken) -> Result<()> {
    atomic_write(path, token.expose().as_bytes(), true)?;
    warden_ipc::restrict_to_owner(path)
        .map_err(|e| WardenError::Config(format!("cannot restrict the token file: {e}")))?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PairedClient {
    name: String,
    hash: String,
    caps: Vec<Capability>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PairingDoc {
    clients: Vec<PairedClient>,
}

fn token_hash(t: &ClientToken) -> String {
    blake3::hash(t.expose().as_bytes()).to_hex().to_string()
}

/// The pairing store. It keeps the BLAKE3 hash of each token, never the token.
///
/// The CLI and the daemon share the file, so the CLI adds its own token without the daemon.
#[derive(Debug, Clone)]
pub struct PairingFile {
    path: PathBuf,
}

impl PairingFile {
    /// Use the store at `path`.
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn load(&self) -> Result<PairingDoc> {
        match std::fs::read(&self.path) {
            Ok(b) => Ok(serde_json::from_slice(&b)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(PairingDoc::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Run `f` while this process and no other process changes the file.
    ///
    /// An in-process mutex and an exclusive lock on `<file>.lock` cover load and save.
    fn with_lock<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        static IN_PROCESS: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = IN_PROCESS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut lock_name = self.path.clone().into_os_string();
        lock_name.push(".lock");
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(PathBuf::from(lock_name))?;
        lock.lock()?;
        let r = f();
        let _ = lock.unlock();
        r
    }

    /// Create a token for a new client and store its hash.
    pub fn add(&self, name: &str, caps: &[Capability]) -> Result<ClientToken> {
        self.with_lock(|| self.add_locked(name, caps))
    }

    fn add_locked(&self, name: &str, caps: &[Capability]) -> Result<ClientToken> {
        let token = ClientToken::generate();
        let mut doc = self.load()?;
        doc.clients.push(PairedClient {
            name: name.to_owned(),
            hash: token_hash(&token),
            caps: caps.to_vec(),
            created_at: Utc::now(),
        });
        atomic_write(&self.path, &serde_json::to_vec_pretty(&doc)?, true)?;
        Ok(token)
    }

    /// List the paired clients. The id is the first 12 characters of the token hash.
    pub fn list(&self) -> Result<Vec<ClientInfo>> {
        Ok(self
            .load()?
            .clients
            .into_iter()
            .map(|c| ClientInfo {
                id: c.hash.chars().take(12).collect(),
                name: c.name,
                capabilities: c.caps,
                paired_at: c.created_at,
            })
            .collect())
    }

    /// Remove the client with this id (as `list` reports it). Return false when none matches.
    pub fn remove(&self, id: &str) -> Result<bool> {
        if id.len() < 8 {
            return Err(WardenError::Config("client id too short".into()));
        }
        self.with_lock(|| self.remove_locked(id))
    }

    fn remove_locked(&self, id: &str) -> Result<bool> {
        let mut doc = self.load()?;
        let n = doc.clients.len();
        doc.clients.retain(|c| !c.hash.starts_with(id));
        if doc.clients.len() == n {
            return Ok(false);
        }
        atomic_write(&self.path, &serde_json::to_vec_pretty(&doc)?, true)?;
        Ok(true)
    }

    /// Capabilities of a token, or `None` when the token is unknown.
    pub fn find(&self, token: &ClientToken) -> Option<Vec<Capability>> {
        let h = token_hash(token);
        // The CLI may replace the file at the same moment. Try twice.
        let doc = self.load().or_else(|_| self.load()).ok()?;
        doc.clients
            .into_iter()
            .find(|c| c.hash == h)
            .map(|c| c.caps)
    }

    /// Return true when the token file holds a token that this store knows.
    pub fn token_file_valid(&self, token_file: &Path) -> bool {
        read_token(token_file)
            .ok()
            .and_then(|t| ClientToken::parse(&t).ok())
            .is_some_and(|t| self.find(&t).is_some())
    }
}

#[async_trait::async_trait]
impl PairingStore for PairingFile {
    async fn lookup(&self, token: &ClientToken) -> Option<Vec<Capability>> {
        self.find(token)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredEntry {
    id: InboxId,
    origin: String,
    label: String,
    captured_at: DateTime<Utc>,
    #[serde(default)]
    provider_hint: Option<String>,
    #[serde(default)]
    expires_at: Option<DateTime<Utc>>,
    nonce: String,
    ct: String,
}

impl StoredEntry {
    fn view(&self) -> InboxEntry {
        InboxEntry {
            id: self.id,
            origin: self.origin.clone(),
            label: self.label.clone(),
            captured_at: self.captured_at,
            provider_hint: self.provider_hint.clone(),
            expires_at: self.expires_at,
        }
    }
}

/// Data of a new inbox entry.
#[derive(Debug)]
pub struct NewInbox {
    /// Origin of the page.
    pub origin: String,
    /// Label.
    pub label: String,
    /// Provider guess.
    pub provider_hint: Option<String>,
    /// End date.
    pub expires_at: Option<DateTime<Utc>>,
}

/// The inbox. Values are sealed with a key derived from the vault key.
#[derive(Debug)]
pub struct InboxStore {
    path: PathBuf,
    lock: Mutex<()>,
}

fn cipher(vault_key: &[u8; 32]) -> XChaCha20Poly1305 {
    let k = blake3::derive_key("aivory-warden inbox v1", vault_key);
    XChaCha20Poly1305::new((&k).into())
}

impl InboxStore {
    /// Use the inbox file at `path`.
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            lock: Mutex::new(()),
        }
    }

    fn load(&self) -> Result<Vec<StoredEntry>> {
        match std::fs::read(&self.path) {
            Ok(b) => Ok(serde_json::from_slice(&b)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e.into()),
        }
    }

    fn save(&self, v: &[StoredEntry]) -> Result<()> {
        atomic_write(&self.path, &serde_json::to_vec_pretty(v)?, true)?;
        Ok(())
    }

    fn guard(&self) -> std::sync::MutexGuard<'_, ()> {
        self.lock.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Add an entry. The value is sealed.
    pub fn add(&self, key: &[u8; 32], meta: NewInbox, value: &SecretValue) -> Result<InboxId> {
        let _g = self.guard();
        let id = InboxId::new();
        let nonce: [u8; 24] = rand::random();
        let ct = cipher(key)
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: value.expose().as_bytes(),
                    aad: id.to_string().as_bytes(),
                },
            )
            .map_err(|_| WardenError::Vault("cannot seal inbox value".into()))?;
        let mut all = self.load()?;
        all.push(StoredEntry {
            id,
            origin: meta.origin,
            label: meta.label,
            captured_at: Utc::now(),
            provider_hint: meta.provider_hint,
            expires_at: meta.expires_at,
            nonce: hex::encode(nonce),
            ct: hex::encode(ct),
        });
        self.save(&all)?;
        Ok(id)
    }

    /// List entries without values.
    pub fn list(&self) -> Result<Vec<InboxEntry>> {
        let _g = self.guard();
        Ok(self.load()?.iter().map(StoredEntry::view).collect())
    }

    /// Number of entries.
    pub fn count(&self) -> usize {
        let _g = self.guard();
        self.load().map(|v| v.len()).unwrap_or(0)
    }

    /// Read the value of an entry. The entry stays until [`InboxStore::remove`].
    pub fn open(&self, key: &[u8; 32], id: InboxId) -> Result<SecretValue> {
        let _g = self.guard();
        let e = self
            .load()?
            .into_iter()
            .find(|e| e.id == id)
            .ok_or_else(|| WardenError::NotFound(format!("inbox entry {id}")))?;
        let bad = || WardenError::Vault("cannot open inbox value".into());
        let nonce = hex::decode(&e.nonce).map_err(|_| bad())?;
        let ct = hex::decode(&e.ct).map_err(|_| bad())?;
        if nonce.len() != 24 {
            return Err(bad());
        }
        let pt = cipher(key)
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ct,
                    aad: id.to_string().as_bytes(),
                },
            )
            .map_err(|_| bad())?;
        Ok(SecretValue::new(String::from_utf8(pt).map_err(|_| bad())?))
    }

    /// Remove an entry. Return false when it does not exist.
    pub fn remove(&self, id: InboxId) -> Result<bool> {
        let _g = self.guard();
        let mut all = self.load()?;
        let n = all.len();
        all.retain(|e| e.id != id);
        if all.len() == n {
            return Ok(false);
        }
        self.save(&all)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_store_keeps_only_hashes() {
        let d = tempfile::tempdir().unwrap();
        let f = PairingFile::new(d.path().join("p.json"));
        let t = f.add("cli", &[Capability::Full]).unwrap();
        let raw = std::fs::read_to_string(d.path().join("p.json")).unwrap();
        assert!(!raw.contains(t.expose()));
        assert_eq!(f.find(&t), Some(vec![Capability::Full]));
        assert_eq!(f.find(&ClientToken::generate()), None);
        let list = f.list().unwrap();
        assert_eq!(list.len(), 1);
        assert!(!f.remove("short").unwrap_or(false));
        assert!(f.remove(&list[0].id).unwrap());
        assert_eq!(f.find(&t), None);
        assert!(!f.remove("0123456789ab").unwrap());
    }

    #[test]
    fn concurrent_pairing_loses_no_token() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("p.json");
        let handles: Vec<_> = (0..8)
            .map(|n| {
                let path = path.clone();
                std::thread::spawn(move || {
                    // Each thread has its own handle, as the CLI and the daemon have.
                    let f = PairingFile::new(path);
                    (0..5)
                        .map(|i| f.add(&format!("c{n}-{i}"), &[Capability::McpUse]).unwrap())
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let tokens: Vec<_> = handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect();
        let f = PairingFile::new(path);
        assert_eq!(f.list().unwrap().len(), 40);
        assert!(tokens.iter().all(|t| f.find(t).is_some()));
    }

    #[test]
    fn token_file_is_owner_only() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("cli.token");
        let t = ClientToken::generate();
        write_token(&p, &t).unwrap();
        assert_eq!(read_token(&p).unwrap(), t.expose());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn inbox_roundtrip_and_no_plaintext() {
        let d = tempfile::tempdir().unwrap();
        let s = InboxStore::new(d.path().join("i.json"));
        let key = [5u8; 32];
        let id = s
            .add(
                &key,
                NewInbox {
                    origin: "https://x".into(),
                    label: "l".into(),
                    provider_hint: None,
                    expires_at: None,
                },
                &SecretValue::new("synthetic-secret-123"),
            )
            .unwrap();
        let raw = std::fs::read_to_string(d.path().join("i.json")).unwrap();
        assert!(!raw.contains("synthetic-secret-123"));
        assert_eq!(s.count(), 1);
        assert_eq!(s.open(&key, id).unwrap().expose(), "synthetic-secret-123");
        assert!(s.open(&[6u8; 32], id).is_err());
        assert!(s.remove(id).unwrap());
        assert_eq!(s.count(), 0);
    }

    #[test]
    fn settings_keep_other_keys() {
        let d = tempfile::tempdir().unwrap();
        let p = Paths::from_home(d.path().to_path_buf());
        std::fs::create_dir_all(&p.config).unwrap();
        std::fs::write(p.settings_file(), r#"{"coffee":{"paid_year":2026}}"#).unwrap();
        let mut s = load_settings(&p).unwrap();
        s.keychain_cache = false;
        save_settings(&p, &s).unwrap();
        set_vault_dir(&p, Path::new("/sync/vault")).unwrap();
        assert!(!load_settings(&p).unwrap().keychain_cache);
        assert_eq!(vault_dir(&p).unwrap(), PathBuf::from("/sync/vault"));
        let raw = std::fs::read_to_string(p.settings_file()).unwrap();
        assert!(raw.contains("paid_year"));
    }
}
