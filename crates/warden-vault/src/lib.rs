//! Aivory Warden vault: a decentral, encrypted, merge-safe vault.
//!
//! Layout: `<vault>/header.json` and `<vault>/ops/<device-id>/<seq>.op`.
//! Every op is one item version, encrypted and signed. Merge is the union of the op files.

pub mod crypto;
pub mod fsutil;
pub mod keychain;
pub mod vault;

pub use crypto::{KdfParams, SecretKey, derive_kek};
pub use keychain::KeyFileCache;
pub use vault::{AuditAction, AuditRecord, DeviceEntry, Vault};
