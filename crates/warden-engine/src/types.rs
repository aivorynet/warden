//! Public value types of the engine.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use warden_core::ItemId;

/// Tuning values of the engine.
#[derive(Debug, Clone, Copy)]
pub struct EngineConfig {
    /// Scheduler tick.
    pub tick: Duration,
    /// Jitter on rotation intervals as a fraction (0.1 = plus or minus 10 percent).
    pub jitter: f64,
    /// First backoff delay after a failure.
    pub backoff_base: Duration,
    /// Largest backoff delay.
    pub backoff_max: Duration,
    /// Minimum time between two MCP-triggered rotations of one item.
    pub mcp_min_interval: Duration,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            tick: Duration::from_secs(60),
            jitter: 0.1,
            backoff_base: Duration::from_secs(60),
            backoff_max: Duration::from_secs(6 * 3600),
            mcp_min_interval: Duration::from_secs(3600),
        }
    }
}

/// Who asks for a rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RotationSource {
    /// An MCP client (rate limited, no `AtomicSwap` without confirmation).
    Mcp,
    /// The CLI.
    Cli,
    /// The desktop app (also the confirmation of an MCP request).
    Desktop,
    /// The scheduler.
    Scheduler,
}

/// Event for notifications.
#[derive(Debug, Clone, PartialEq)]
pub enum EngineEvent {
    /// A rotation finished. `complete` is false when a sink still fails.
    Rotated {
        /// The item.
        item_id: ItemId,
        /// Display name.
        name: String,
        /// True when all sinks hold the new value.
        complete: bool,
    },
    /// A rotation or a revoke failed.
    Failed {
        /// The item.
        item_id: ItemId,
        /// Display name.
        name: String,
        /// Error text (never a secret).
        error: String,
        /// Next retry.
        next_retry: Option<DateTime<Utc>>,
    },
    /// An item is due but is not rotated automatically (manual provider).
    Due {
        /// The item.
        item_id: ItemId,
        /// Display name.
        name: String,
    },
    /// An item expires soon and the engine does not rotate it.
    ExpiringSoon {
        /// The item.
        item_id: ItemId,
        /// Display name.
        name: String,
        /// End date.
        expires_at: DateTime<Utc>,
    },
    /// The vault is locked, so the scheduler skips its pass.
    Locked,
    /// The old token is revoked later.
    RevokePending {
        /// The item.
        item_id: ItemId,
        /// Display name.
        name: String,
        /// The revoke runs at or after this time.
        due: DateTime<Utc>,
    },
}

/// Status of an item in the engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ItemStatus {
    /// Nothing runs.
    Idle,
    /// A rotation runs.
    Rotating,
    /// The last attempt failed.
    Failed {
        /// Error text.
        error: String,
        /// Failed attempts in a row.
        attempts: u32,
        /// Next retry.
        next_retry: DateTime<Utc>,
    },
    /// The new value is in place. Only the revoke of the old token remains.
    RevokePending {
        /// The revoke runs at or after this time.
        due: DateTime<Utc>,
    },
}

/// Result of one sink write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SinkOutcome {
    /// Description of the sink.
    pub sink: String,
    /// True when the write and the read back succeeded.
    pub ok: bool,
    /// Error text.
    pub error: Option<String>,
}

/// State of the revoke of the old token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevokeState {
    /// Nothing to revoke.
    NotNeeded,
    /// Queued for the given time.
    Pending {
        /// Due time.
        due: DateTime<Utc>,
    },
}

/// Result of a rotation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RotationReport {
    /// The item.
    pub item_id: ItemId,
    /// Rotation class.
    pub class: warden_core::RotationClass,
    /// Id of the new token at the provider.
    pub new_provider_token_id: String,
    /// End date of the new token.
    pub expires_at: Option<DateTime<Utc>>,
    /// One entry per sink.
    pub sinks: Vec<SinkOutcome>,
    /// State of the revoke.
    pub revoke: RevokeState,
    /// True when all sinks hold the new value. When false, the item status is `Failed`.
    pub complete: bool,
}

/// Result of one queued revoke.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeReport {
    /// The item.
    pub item_id: ItemId,
    /// Token id that was revoked (or that failed).
    pub provider_token_id: String,
    /// True when the revoke is done.
    pub done: bool,
    /// Error text when it failed.
    pub error: Option<String>,
}

/// Outcome of [`crate::Engine::request_rotation`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RotationRequestOutcome {
    /// The item rotated.
    Rotated(RotationReport),
    /// The user must confirm in the desktop app.
    NeedsConfirmation,
    /// The rate limit applies. Retry at the given time.
    RateLimited {
        /// Earliest next request.
        retry_at: DateTime<Utc>,
    },
}

/// Summary of one scheduler pass.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct TickReport {
    /// The pass was skipped because the vault is locked.
    pub skipped_locked: bool,
    /// Items that the pass rotated (complete or not).
    pub rotated: Vec<ItemId>,
    /// Items whose rotation failed.
    pub failed: Vec<ItemId>,
    /// Revokes that the pass executed.
    pub revokes: Vec<RevokeReport>,
}
