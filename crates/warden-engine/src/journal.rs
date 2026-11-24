//! The intent journal: one JSON file per in-flight rotation.
//!
//! The new secret value is stored in the journal only in sealed form (XChaCha20-Poly1305
//! with the vault key), so a crash between "provider issued the token" and "vault holds the
//! token" loses nothing.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use warden_core::{ItemId, Result, RotationClass, WardenError};
use warden_vault::fsutil::atomic_write;

/// The token that the provider issued, with the value sealed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issued {
    /// Hex of nonce and ciphertext of the new value.
    pub sealed: String,
    /// Id of the new token at the provider.
    pub provider_token_id: String,
    /// End date of the new token.
    pub expires_at: Option<DateTime<Utc>>,
}

/// A queued revoke of the old token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeTask {
    /// The revoke runs at or after this time.
    pub due: DateTime<Utc>,
    /// Number of failed revoke attempts.
    pub attempts: u32,
}

/// State of one rotation. Written before and after every step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    /// Id of the rotation (the file name).
    pub id: Uuid,
    /// The item that rotates.
    pub item_id: ItemId,
    /// Rotation class at the start.
    pub class: RotationClass,
    /// Start time.
    pub started_at: DateTime<Utc>,
    /// Id of the token that the rotation replaces.
    pub old_provider_token_id: Option<String>,
    /// Name for the new token.
    pub token_name: String,
    /// Set when the provider issued the new token.
    pub issued: Option<Issued>,
    /// The new value is in the vault.
    pub stored: bool,
    /// All sinks hold the new value (and read back).
    pub sinks_done: bool,
    /// Set when only the revoke of the old token remains.
    pub revoke: Option<RevokeTask>,
    /// Failed forward attempts.
    pub attempts: u32,
    /// Next forward attempt.
    pub next_attempt: Option<DateTime<Utc>>,
    /// Last error text (never a secret).
    pub last_error: Option<String>,
}

/// The journal directory.
#[derive(Debug, Clone)]
pub struct Journal {
    dir: PathBuf,
}

impl Journal {
    /// Open the journal in `dir`. The directory is created when needed.
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    /// Directory of the journal.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path(&self, id: Uuid) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    /// Write an entry atomically (temp file, fsync, rename).
    pub fn save(&self, e: &JournalEntry) -> Result<()> {
        atomic_write(&self.path(e.id), &serde_json::to_vec_pretty(e)?, true)?;
        Ok(())
    }

    /// Delete an entry.
    pub fn remove(&self, id: Uuid) -> Result<()> {
        match fs::remove_file(self.path(id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Load one entry by id. `None` when the entry is gone or does not parse.
    pub fn load(&self, id: Uuid) -> Result<Option<JournalEntry>> {
        match fs::read(self.path(id)) {
            Ok(b) => Ok(serde_json::from_slice(&b).ok()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Load all entries, oldest first. Files that do not parse are skipped.
    pub fn load_all(&self) -> Result<Vec<JournalEntry>> {
        let mut out = Vec::new();
        for f in fs::read_dir(&self.dir)? {
            let p = f?.path();
            if p.extension().and_then(|x| x.to_str()) != Some("json") {
                continue;
            }
            match serde_json::from_slice::<JournalEntry>(&fs::read(&p)?) {
                Ok(e) => out.push(e),
                Err(e) => tracing::warn!("skip unreadable journal file: {e}"),
            }
        }
        out.sort_by_key(|e| (e.started_at, e.id));
        Ok(out)
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Seal `value` with the vault key. `aad` binds the ciphertext to the rotation id.
pub(crate) fn seal(key: &[u8; 32], aad: &str, value: &str) -> Result<String> {
    let c = XChaCha20Poly1305::new(key.into());
    let nonce: [u8; 24] = rand::random();
    let ct = c
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: value.as_bytes(),
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| WardenError::Vault("journal seal failed".into()))?;
    let mut all = nonce.to_vec();
    all.extend(ct);
    Ok(hex(&all))
}

/// Open a value sealed by [`seal`].
pub(crate) fn open(key: &[u8; 32], aad: &str, sealed: &str) -> Result<String> {
    let bad = || WardenError::Vault("journal entry cannot be opened".into());
    let all = unhex(sealed).ok_or_else(bad)?;
    if all.len() < 24 {
        return Err(bad());
    }
    let (n, ct) = all.split_at(24);
    let c = XChaCha20Poly1305::new(key.into());
    let pt = c
        .decrypt(
            XNonce::from_slice(n),
            Payload {
                msg: ct,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| bad())?;
    String::from_utf8(pt).map_err(|_| bad())
}
