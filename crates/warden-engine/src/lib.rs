//! Rotation engine of Aivory Warden: state machine, intent journal, scheduler and
//! rotator lease.
//!
//! Flow per class:
//!
//! - `Overlap`: journal intent, issue new token, write all sinks and read them back, store the
//!   value in the vault, queue the revoke of the old token (runs after the grace time).
//! - `AtomicSwap`: journal intent, issue new token, seal it into the journal, store it in the
//!   vault, write the sinks. Sink failures retry forward. The old value never returns.
//!
//! Every step writes the journal first. [`Engine::recover`] resumes each entry on startup.

pub mod journal;
mod revoke;
mod rotate;
mod scheduler;
mod types;

pub use types::{
    EngineConfig, EngineEvent, ItemStatus, RevokeReport, RevokeState, RotationReport,
    RotationRequestOutcome, RotationSource, SinkOutcome, TickReport,
};

use chrono::{DateTime, Utc};
use journal::Journal;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use tokio::sync::broadcast;
use warden_core::{
    Clock, DeviceId, Item, ItemId, Provider, ProviderRef, Result, SecretValue, Settings, Sink,
    SinkSpec, WardenError,
};
use warden_vault::Vault;

/// Name of the secret that holds the token value in a vault item.
pub const TOKEN_SECRET: &str = "token";

/// Builds a provider for a provider reference. Tests inject fakes.
pub type ProviderFactory = Arc<dyn Fn(&ProviderRef) -> Result<Box<dyn Provider>> + Send + Sync>;

/// Builds a sink for a sink spec. Tests inject fakes.
pub type SinkFactory = Arc<dyn Fn(&SinkSpec) -> Result<Box<dyn Sink>> + Send + Sync>;

/// The production provider factory (`warden_providers::build`).
pub fn default_provider_factory() -> ProviderFactory {
    Arc::new(warden_providers::build)
}

#[derive(Default)]
pub(crate) struct State {
    pub statuses: HashMap<ItemId, ItemStatus>,
    pub busy: HashSet<ItemId>,
    pub mcp_last: HashMap<ItemId, DateTime<Utc>>,
    pub due_notified: HashSet<ItemId>,
    pub expiring_notified: HashSet<ItemId>,
    pub locked: bool,
    pub locked_notified: bool,
    pub fault: Option<String>,
}

/// The rotation engine. Share it with `Arc`.
pub struct Engine {
    pub(crate) vault: Arc<Mutex<Vault>>,
    pub(crate) providers: ProviderFactory,
    pub(crate) sinks: SinkFactory,
    pub(crate) settings: Mutex<Settings>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) journal: Journal,
    pub(crate) device_id: DeviceId,
    pub(crate) config: EngineConfig,
    pub(crate) events: broadcast::Sender<EngineEvent>,
    pub(crate) state: Mutex<State>,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("device_id", &self.device_id)
            .field("journal", &self.journal)
            .finish_non_exhaustive()
    }
}

impl Engine {
    /// Create an engine with the default [`EngineConfig`].
    ///
    /// `journal_dir` is created when it does not exist. `device_id` is this device: the
    /// engine rotates only items with `rotator_device == device_id`.
    pub fn new(
        vault: Arc<Mutex<Vault>>,
        providers: ProviderFactory,
        sinks: SinkFactory,
        settings: Settings,
        clock: Arc<dyn Clock>,
        journal_dir: impl Into<PathBuf>,
        device_id: DeviceId,
    ) -> Result<Self> {
        Self::with_config(
            vault,
            providers,
            sinks,
            settings,
            clock,
            journal_dir,
            device_id,
            EngineConfig::default(),
        )
    }

    /// Like [`Engine::new`] with an explicit [`EngineConfig`].
    #[allow(clippy::too_many_arguments)]
    pub fn with_config(
        vault: Arc<Mutex<Vault>>,
        providers: ProviderFactory,
        sinks: SinkFactory,
        settings: Settings,
        clock: Arc<dyn Clock>,
        journal_dir: impl Into<PathBuf>,
        device_id: DeviceId,
        config: EngineConfig,
    ) -> Result<Self> {
        let (events, _) = broadcast::channel(256);
        Ok(Self {
            vault,
            providers,
            sinks,
            settings: Mutex::new(settings),
            clock,
            journal: Journal::new(journal_dir)?,
            device_id,
            config,
            events,
            state: Mutex::new(State::default()),
        })
    }

    /// Subscribe to engine events.
    pub fn subscribe(&self) -> broadcast::Receiver<EngineEvent> {
        self.events.subscribe()
    }

    /// Replace the global settings.
    pub fn set_settings(&self, settings: Settings) {
        *lock(&self.settings) = settings;
    }

    /// Tell the engine that the vault is locked (or unlocked). While locked, the scheduler
    /// skips its pass and emits [`EngineEvent::Locked`].
    pub fn set_locked(&self, locked: bool) {
        let mut s = lock(&self.state);
        s.locked = locked;
        if !locked {
            s.locked_notified = false;
        }
    }

    /// Current status of an item.
    pub fn status(&self, item: &ItemId) -> ItemStatus {
        lock(&self.state)
            .statuses
            .get(item)
            .cloned()
            .unwrap_or(ItemStatus::Idle)
    }

    /// Test hook: simulate a crash once, right after the named step. Steps: `intent`,
    /// `issued`, `sink<N>`, `sinks`, `stored`, `revoke_queued`, `revoke_called`.
    #[doc(hidden)]
    pub fn inject_fault(&self, point: &str) {
        lock(&self.state).fault = Some(point.to_owned());
    }

    pub(crate) fn checkpoint(&self, point: &str) -> Result<()> {
        let mut s = lock(&self.state);
        if s.fault.as_deref() == Some(point) {
            s.fault = None;
            return Err(WardenError::Config(format!("{INJECTED} {point}")));
        }
        Ok(())
    }

    pub(crate) fn emit(&self, e: EngineEvent) {
        let _ = self.events.send(e);
    }

    pub(crate) fn with_vault<T>(&self, f: impl FnOnce(&mut Vault) -> Result<T>) -> Result<T> {
        f(&mut lock(&self.vault))
    }

    pub(crate) fn item(&self, id: &ItemId) -> Result<Item> {
        self.with_vault(|v| {
            v.get(id)
                .cloned()
                .ok_or_else(|| WardenError::NotFound(format!("item {id}")))
        })
    }

    pub(crate) fn secret_of(&self, id: &ItemId) -> Result<SecretValue> {
        self.with_vault(|v| v.secret(id, TOKEN_SECRET))
    }

    pub(crate) fn vault_key(&self) -> [u8; 32] {
        *lock(&self.vault).export_vault_key()
    }

    pub(crate) fn set_status(&self, id: ItemId, s: ItemStatus) {
        lock(&self.state).statuses.insert(id, s);
    }
}

pub(crate) const INJECTED: &str = "injected crash after";

pub(crate) fn is_injected(e: &WardenError) -> bool {
    matches!(e, WardenError::Config(m) if m.starts_with(INJECTED))
}

/// Lock a mutex. A poisoned lock still gives access (the data stays consistent per call).
pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}
