//! Error type of Aivory Warden.

use std::time::Duration;

/// Result alias with [`WardenError`].
pub type Result<T, E = WardenError> = std::result::Result<T, E>;

/// Error of any Warden operation.
#[derive(Debug, thiserror::Error)]
pub enum WardenError {
    /// The provider refused the credential (401/403).
    #[error("provider authentication failed: {0}")]
    ProviderAuth(String),
    /// The provider rate limit applies.
    #[error("provider rate limited (retry after {retry_after:?})")]
    ProviderRateLimited {
        /// Wait time that the provider asked for.
        retry_after: Option<Duration>,
    },
    /// The provider does not support the operation.
    #[error("provider does not support: {0}")]
    ProviderUnsupported(String),
    /// Other provider failure.
    #[error("provider error: {0}")]
    Provider(String),
    /// A sink failed.
    #[error("sink error: {0}")]
    Sink(String),
    /// A vault failure.
    #[error("vault error: {0}")]
    Vault(String),
    /// The vault is locked.
    #[error("vault is locked")]
    Locked,
    /// An IPC failure.
    #[error("ipc error: {0}")]
    Ipc(String),
    /// A not-found failure.
    #[error("not found: {0}")]
    NotFound(String),
    /// An I/O failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// A JSON failure.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// A configuration failure.
    #[error("config error: {0}")]
    Config(String),
}
