//! The background daemon: vault, engine, scheduler and the IPC handler.

use crate::paths::Paths;
use crate::store::{self, InboxStore, NewInbox, PairingFile};
use async_trait::async_trait;
use chrono::Utc;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use warden_coffee::CoffeeStore;
use warden_core::ipc::{
    AuditEntry, Capability, CoffeeInfo, DeviceInfo, ItemDraft, ItemStatus, ItemSummary, Request,
    Response, StatusInfo,
};
use warden_core::{
    Clock, DeviceId, Item, ItemId, ItemKind, Result, SecretValue, Settings, SystemClock,
    WardenError, next_rotation,
};
use warden_engine::{
    Engine, EngineConfig, EngineEvent, ItemStatus as EngineStatus, ProviderFactory,
    RotationRequestOutcome, RotationSource, SinkFactory, TOKEN_SECRET,
};
use warden_ipc::{Handler, Server, Session};
use warden_mcp::proxy::{self, HttpCall};
use warden_vault::{AuditAction, KeyFileCache, SecretKey, Vault, keychain};

/// Longest rotation interval that a client without the `Full` capability may set.
const MAX_PARTIAL_INTERVAL: Duration = Duration::from_secs(365 * 24 * 3600);

/// Return the reason when `new` weakens `current` in a way that needs a `Full` session.
fn weakens_policy(
    current: &warden_core::RotationPolicy,
    new: &warden_core::RotationPolicy,
    default_interval: Duration,
) -> Option<&'static str> {
    if current.auto_rotate && !new.auto_rotate {
        return Some("turning rotation off needs confirmation in the desktop app");
    }
    let old_interval = current.interval.unwrap_or(default_interval);
    let new_interval = new.interval.unwrap_or(default_interval);
    if new_interval > old_interval || new_interval > MAX_PARTIAL_INTERVAL {
        return Some("a longer rotation interval needs confirmation in the desktop app");
    }
    if new.lead_time.is_zero() && !current.lead_time.is_zero() {
        return Some("removing the lead time needs confirmation in the desktop app");
    }
    if new.grace > current.grace {
        return Some("a longer grace period needs confirmation in the desktop app");
    }
    None
}

/// Host part of `url` for the audit log. No path, query or user info.
fn url_host(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let auth = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = auth.rsplit_once('@').map_or(auth, |(_, h)| h);
    host.chars().take(253).collect()
}

/// Write `value` to every place in `specs` and read it back. Return the failures.
async fn write_sinks(specs: &[warden_core::SinkSpec], value: &SecretValue) -> Vec<String> {
    let mut failed = Vec::new();
    for spec in specs {
        let res = match warden_sinks::build(spec) {
            Err(e) => Err(format!("{spec:?}: {e}")),
            Ok(sink) => match sink.write(value).await {
                Err(e) => Err(format!("{}: {e}", sink.describe())),
                Ok(()) => match sink.read_back_matches(value).await {
                    Ok(true) => Ok(()),
                    Ok(false) => Err(format!("{}: read back does not match", sink.describe())),
                    Err(e) => Err(format!("{}: {e}", sink.describe())),
                },
            },
        };
        if let Err(e) = res {
            failed.push(e);
        }
    }
    failed
}

/// Everything that exists only while the vault is unlocked.
#[derive(Clone)]
struct Unlocked {
    vault: Arc<Mutex<Vault>>,
    engine: Arc<Engine>,
}

/// State and logic of the daemon. It implements the IPC [`Handler`].
pub struct Daemon {
    paths: Paths,
    vault_override: Option<PathBuf>,
    settings: Mutex<Settings>,
    unlocked: Mutex<Option<Unlocked>>,
    inbox: InboxStore,
    clock: Arc<dyn Clock>,
    engine_cfg: EngineConfig,
    keychain_enabled: bool,
    key_file: Option<KeyFileCache>,
    notify_enabled: bool,
    coffee_lock: Arc<Mutex<()>>,
}

impl std::fmt::Debug for Daemon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Daemon").finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn error(code: &str, message: impl Into<String>) -> Response {
    Response::Error {
        code: code.into(),
        message: message.into(),
    }
}

/// Map a Warden error to an IPC error response. The text never holds a secret.
fn err_resp(e: &WardenError) -> Response {
    let code = match e {
        WardenError::Locked => "locked",
        WardenError::NotFound(_) => "not_found",
        WardenError::Config(_) => "bad_request",
        WardenError::ProviderAuth(_) => "provider_auth",
        WardenError::ProviderRateLimited { .. } => "rate_limited",
        WardenError::ProviderUnsupported(_) => "unsupported",
        WardenError::Provider(_) => "provider",
        WardenError::Sink(_) => "sink",
        WardenError::Vault(_) => "vault",
        _ => "internal",
    };
    error(code, e.to_string())
}

fn valid_slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 40
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

fn read_device_id(paths: &Paths) -> Option<DeviceId> {
    std::fs::read_to_string(paths.device_id_file())
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn vault_id_of(dir: &std::path::Path) -> Option<warden_core::VaultId> {
    let raw = std::fs::read(dir.join("header.json")).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    serde_json::from_value(v.get("vault_id")?.clone()).ok()
}

impl Daemon {
    /// Create the daemon state. Nothing is unlocked yet.
    pub fn new(paths: Paths, vault_override: Option<PathBuf>) -> Result<Self> {
        let settings = store::load_settings(&paths)?;
        let mut engine_cfg = EngineConfig::default();
        if cfg!(debug_assertions)
            && let Some(ms) = std::env::var("WARDEN_TICK_MS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
        {
            engine_cfg.tick = Duration::from_millis(ms);
        }
        let flag = |k: &str| std::env::var_os(k).is_some_and(|v| !v.is_empty());
        Ok(Self {
            inbox: InboxStore::new(paths.inbox_file()),
            paths,
            vault_override,
            settings: Mutex::new(settings),
            unlocked: Mutex::new(None),
            clock: Arc::new(SystemClock),
            engine_cfg,
            keychain_enabled: !flag("WARDEN_NO_KEYCHAIN"),
            key_file: None,
            notify_enabled: !flag("WARDEN_NO_NOTIFY"),
            coffee_lock: Arc::new(Mutex::new(())),
        })
    }

    /// Cache the vault key in a file (mode 0600 on Unix). Opt-in, for headless Linux.
    #[must_use]
    pub fn with_key_file(mut self, path: PathBuf) -> Self {
        self.key_file = Some(KeyFileCache::new(path));
        self
    }

    fn vault_dir(&self) -> Result<PathBuf> {
        match &self.vault_override {
            Some(p) => Ok(p.clone()),
            None => store::vault_dir(&self.paths),
        }
    }

    fn settings(&self) -> Settings {
        *lock(&self.settings)
    }

    fn current(&self) -> Option<Unlocked> {
        lock(&self.unlocked).clone()
    }

    fn require(&self) -> std::result::Result<Unlocked, Response> {
        self.current()
            .ok_or_else(|| error("locked", "vault is locked"))
    }

    /// Open the vault with the key from the OS keychain, if one is cached.
    pub async fn try_auto_unlock(&self) {
        if self.paths.soft_lock_file().exists() {
            tracing::info!("vault is soft locked, waiting for a quick unlock");
            return;
        }
        let Ok(dir) = self.vault_dir() else { return };
        let Some(vid) = vault_id_of(&dir) else { return };
        let Some(key) = self.load_cached_key(&vid) else {
            return;
        };
        let local = self.paths.device_dir();
        let opened =
            tokio::task::spawn_blocking(move || Vault::open_with_key(&dir, &key, &local)).await;
        match opened {
            Ok(Ok(v)) => match self.install(v, false).await {
                Ok(()) => tracing::info!("vault unlocked from the keychain"),
                Err(e) => tracing::warn!("cannot start the engine: {e}"),
            },
            Ok(Err(e)) => tracing::warn!("cached key does not open the vault: {e}"),
            Err(e) => tracing::warn!("unlock task failed: {e}"),
        }
    }

    /// Read the cached vault key: the OS keychain first, then the key file.
    fn load_cached_key(&self, vid: &warden_core::VaultId) -> Option<zeroize::Zeroizing<[u8; 32]>> {
        let mut key = None;
        if self.keychain_enabled {
            match keychain::load(vid) {
                Ok(k) => key = k,
                Err(e) => tracing::warn!("keychain read failed: {e}"),
            }
        }
        if key.is_none()
            && let Some(kf) = &self.key_file
        {
            match kf.load() {
                Ok(k) => key = k,
                Err(e) => tracing::warn!("key file read failed: {e}"),
            }
        }
        key
    }

    /// Remove every cached key and the soft lock marker.
    fn forget_cached_key(&self) {
        let _ = std::fs::remove_file(self.paths.soft_lock_file());
        if self.keychain_enabled
            && let Ok(dir) = self.vault_dir()
            && let Some(vid) = vault_id_of(&dir)
            && let Err(e) = keychain::clear(&vid)
        {
            tracing::warn!("cannot clear the keychain entry: {e}");
        }
        if let Some(kf) = &self.key_file
            && let Err(e) = kf.clear()
        {
            tracing::warn!("cannot remove the key file: {e}");
        }
    }

    /// Append one entry to the device-local audit log. A failure is logged and ignored.
    fn local_audit(&self, action: &str, detail: &str) {
        use std::io::Write;
        let entry = AuditEntry {
            at: self.clock.now(),
            device: read_device_id(&self.paths).unwrap_or(DeviceId(uuid::Uuid::nil())),
            item: None,
            action: action.into(),
            detail: detail.into(),
        };
        let path = self.paths.local_audit_file();
        let res = (|| -> std::io::Result<()> {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)?;
            writeln!(f, "{}", serde_json::to_string(&entry)?)
        })();
        if let Err(e) = res {
            tracing::warn!("cannot write the local audit log: {e}");
        }
    }

    fn read_local_audit(&self) -> Vec<AuditEntry> {
        std::fs::read_to_string(self.paths.local_audit_file())
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    async fn unlock_quick(&self) -> Response {
        if !self.settings().quick_unlock {
            self.local_audit("quick_unlock_refused", "quick unlock is off");
            return error("quick_unlock_off", "quick unlock is off");
        }
        if self.current().is_some() {
            return Response::Ok;
        }
        let dir = match self.vault_dir() {
            Ok(d) => d,
            Err(e) => return err_resp(&e),
        };
        let key = vault_id_of(&dir).and_then(|vid| self.load_cached_key(&vid));
        let Some(key) = key else {
            self.local_audit("quick_unlock_refused", "no cached key");
            return error(
                "no_cached_key",
                "no cached key on this device: unlock with the password",
            );
        };
        let local = self.paths.device_dir();
        let opened =
            tokio::task::spawn_blocking(move || Vault::open_with_key(&dir, &key, &local)).await;
        let vault = match opened {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                self.local_audit("quick_unlock_refused", "cached key does not open the vault");
                return error("unlock_failed", e.to_string());
            }
            Err(e) => return error("internal", e.to_string()),
        };
        match self.install(vault, false).await {
            Ok(()) => {
                self.local_audit("quick_unlock", "vault unlocked with the OS user check");
                Response::Ok
            }
            Err(e) => err_resp(&e),
        }
    }

    async fn install(&self, vault: Vault, cache_key: bool) -> Result<()> {
        let _ = std::fs::remove_file(self.paths.soft_lock_file());
        let device = vault.device_id();
        if cache_key && self.keychain_enabled {
            let key = vault.export_vault_key();
            if let Err(e) = keychain::store(&vault.vault_id(), &key) {
                tracing::warn!("cannot cache the key in the keychain: {e}");
            }
        }
        if let Some(kf) = &self.key_file
            && let Err(e) = kf.store(&vault.export_vault_key())
        {
            tracing::warn!("cannot write the key file: {e}");
        }
        if let Err(e) = std::fs::write(self.paths.device_id_file(), device.to_string()) {
            tracing::warn!("cannot write the device id file: {e}");
        }
        let vault = Arc::new(Mutex::new(vault));
        let providers: ProviderFactory = warden_engine::default_provider_factory();
        let sinks: SinkFactory = Arc::new(warden_sinks::build);
        let engine = Arc::new(Engine::with_config(
            Arc::clone(&vault),
            providers,
            sinks,
            self.settings(),
            Arc::clone(&self.clock),
            self.paths.journal_dir(),
            device,
            self.engine_cfg,
        )?);
        if let Err(e) = engine.recover().await {
            tracing::warn!("journal recovery failed: {e}");
        }
        self.spawn_event_pump(&engine);
        *lock(&self.unlocked) = Some(Unlocked { vault, engine });
        Ok(())
    }

    fn spawn_event_pump(&self, engine: &Engine) {
        let mut rx = engine.subscribe();
        let enabled = self.notify_enabled;
        let paths = self.paths.clone();
        let lk = Arc::clone(&self.coffee_lock);
        let clock = Arc::clone(&self.clock);
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(ev) => {
                        if let Some((title, body)) = describe_event(&ev) {
                            notify(enabled, title, body).await;
                        }
                        if matches!(ev, EngineEvent::Rotated { complete: true, .. }) {
                            let reminder = store::load_settings(&paths)
                                .map(|s| s.coffee_reminder)
                                .unwrap_or(true);
                            let note = coffee_take(&paths, &lk, |st| {
                                warden_coffee::record_rotation(st);
                                warden_coffee::take_note(
                                    st,
                                    warden_coffee::Moment::FirstRotation,
                                    reminder,
                                    clock.as_ref(),
                                )
                            });
                            if let Some(n) = note {
                                notify(enabled, n.title, n.body).await;
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                }
            }
        });
    }

    async fn unlock(&self, password: SecretValue, secret_key: SecretValue) -> Response {
        if self.current().is_some() {
            return Response::Ok;
        }
        let sk: SecretKey = match secret_key.expose().parse() {
            Ok(k) => k,
            Err(e) => return err_resp(&e),
        };
        let dir = match self.vault_dir() {
            Ok(d) => d,
            Err(e) => return err_resp(&e),
        };
        let local = self.paths.device_dir();
        let opened =
            tokio::task::spawn_blocking(move || Vault::open(&dir, password.expose(), &sk, &local))
                .await;
        let vault = match opened {
            Ok(Ok(v)) => v,
            Ok(Err(_)) => return error("unlock_failed", "password or Secret Key is wrong"),
            Err(e) => return error("internal", e.to_string()),
        };
        let cache = self.settings().keychain_cache;
        match self.install(vault, cache).await {
            Ok(()) => Response::Ok,
            Err(e) => err_resp(&e),
        }
    }

    /// Lock the vault. With quick unlock on and `forget` false, the key stays cached (soft
    /// lock) and a marker file keeps the daemon locked after a restart. Otherwise the cached
    /// key is removed, so a locked daemon stays locked after a restart.
    fn lock_vault(&self, forget: bool) -> Response {
        let taken = lock(&self.unlocked).take();
        if let Some(u) = &taken {
            u.engine.set_locked(true);
        }
        if !forget && self.settings().quick_unlock {
            if let Err(e) = std::fs::write(self.paths.soft_lock_file(), b"soft lock") {
                // Without the marker a restart would open the vault again: forget the key.
                tracing::warn!("cannot write the soft lock marker: {e}");
                self.forget_cached_key();
            }
        } else {
            self.forget_cached_key();
        }
        Response::Ok
    }

    fn summary(&self, item: &Item, settings: &Settings, engine: &Engine) -> ItemSummary {
        let now = self.clock.now();
        let next = next_rotation(item, settings, now);
        let (status, last_error, next_retry) = match engine.status(&item.id) {
            EngineStatus::Rotating => (ItemStatus::Rotating, None, None),
            EngineStatus::Failed {
                error, next_retry, ..
            } => (ItemStatus::Failed, Some(error), Some(next_retry)),
            _ if item.provider.kind == warden_core::ProviderKind::Manual => {
                (ItemStatus::Reminder, None, None)
            }
            _ if next.is_some_and(|n| n <= now) => (ItemStatus::Due, None, None),
            _ => (ItemStatus::Healthy, None, None),
        };
        ItemSummary {
            id: item.id,
            name: item.name.clone(),
            provider: item.provider.kind,
            kind: item.kind,
            expires_at: item.expires_at,
            next_rotation: next,
            sink_count: item.sinks.len(),
            auto_rotate: item.policy.auto_rotate,
            status,
            last_error,
            next_retry,
        }
    }

    /// Check a draft and build the item. The caller holds the vault.
    fn new_item(&self, v: &Vault, draft: ItemDraft) -> std::result::Result<Item, Response> {
        if draft.name.trim().is_empty() {
            return Err(error("bad_request", "name is empty"));
        }
        if !valid_slug(&draft.slug) {
            return Err(error(
                "bad_request",
                "slug must have 1 to 40 characters from a-z, 0-9, - and _",
            ));
        }
        if v.items()
            .iter()
            .any(|i| i.name.eq_ignore_ascii_case(&draft.name) || i.slug == draft.slug)
        {
            return Err(error("conflict", "an item with this name or slug exists"));
        }
        if let ItemKind::Derived { parent } = draft.kind
            && v.get(&parent).is_none_or(|p| p.kind != ItemKind::Admin)
        {
            return Err(error(
                "bad_request",
                "parent must be an existing admin item",
            ));
        }
        for spec in &draft.sinks {
            if let Err(e) = warden_sinks::build(spec) {
                return Err(error("bad_request", format!("invalid sink: {e}")));
            }
        }
        Ok(Item {
            id: ItemId::new(),
            name: draft.name,
            slug: draft.slug,
            kind: draft.kind,
            provider: draft.provider,
            provider_token_id: None,
            expires_at: draft.expires_at,
            created_at: self.clock.now(),
            rotated_at: None,
            policy: draft.policy,
            sinks: draft.sinks,
            mcp: draft.mcp,
            rotator_device: v.device_id(),
            tags: draft.tags,
        })
    }

    async fn add_item(&self, draft: ItemDraft, secret: SecretValue) -> Response {
        let u = match self.require() {
            Ok(u) => u,
            Err(r) => return r,
        };
        let item = {
            let mut v = lock(&u.vault);
            let item = match self.new_item(&v, draft) {
                Ok(i) => i,
                Err(r) => return r,
            };
            let secrets = [(TOKEN_SECRET.to_owned(), secret.clone())]
                .into_iter()
                .collect();
            if let Err(e) = v.put(item.clone(), secrets) {
                return err_resp(&e);
            }
            item
        };
        // The places get the value now, not only at the first rotation.
        let failed = write_sinks(&item.sinks, &secret).await;
        if failed.is_empty() {
            Response::Added { item: item.id }
        } else {
            error(
                "sinks_incomplete",
                format!(
                    "token {} is stored, but a place failed: {}",
                    item.id,
                    failed.join("; ")
                ),
            )
        }
    }

    /// Delete an item. Refuse while derived items still use it as their parent.
    fn delete_item(&self, id: ItemId) -> Response {
        let u = match self.require() {
            Ok(u) => u,
            Err(r) => return r,
        };
        let mut v = lock(&u.vault);
        let children: Vec<String> = v
            .items()
            .iter()
            .filter(|i| i.kind == ItemKind::Derived { parent: id })
            .map(|i| i.name.clone())
            .collect();
        if !children.is_empty() {
            return error(
                "conflict",
                format!(
                    "derived tokens use this token: {}. Delete them first",
                    children.join(", ")
                ),
            );
        }
        match v.delete(&id) {
            Ok(()) => Response::Ok,
            Err(e) => err_resp(&e),
        }
    }

    /// Create a derived item. The engine makes the first token at the provider.
    async fn create_derived(&self, draft: ItemDraft) -> Response {
        let u = match self.require() {
            Ok(u) => u,
            Err(r) => return r,
        };
        if !matches!(draft.kind, ItemKind::Derived { .. }) {
            return error("bad_request", "a derived item needs a parent");
        }
        let item = {
            let v = lock(&u.vault);
            match self.new_item(&v, draft) {
                Ok(i) => i,
                Err(r) => return r,
            }
        };
        let id = item.id;
        match u.engine.create_derived(item).await {
            Ok(r) if r.complete => Response::Added { item: id },
            Ok(r) => {
                let failed: Vec<String> = r
                    .sinks
                    .iter()
                    .filter(|s| !s.ok)
                    .map(|s| format!("{}: {}", s.sink, s.error.as_deref().unwrap_or("failed")))
                    .collect();
                error(
                    "sinks_incomplete",
                    format!(
                        "token {id} is created and stored, but a sink failed (retry runs later): {}",
                        failed.join("; ")
                    ),
                )
            }
            Err(e) => err_resp(&e),
        }
    }

    /// Move the rotator role of one item or of all items to another device.
    fn handover(&self, item: Option<ItemId>, to: DeviceId) -> Response {
        let u = match self.require() {
            Ok(u) => u,
            Err(r) => return r,
        };
        let mut v = lock(&u.vault);
        if !v.devices().iter().any(|d| d.id == to) {
            return error("not_found", format!("device {to}"));
        }
        let targets: Vec<Item> = match item {
            Some(id) => match v.get(&id) {
                Some(i) => vec![i.clone()],
                None => return error("not_found", format!("item {id}")),
            },
            None => v.items().into_iter().cloned().collect(),
        };
        for mut it in targets {
            if it.rotator_device == to {
                continue;
            }
            it.rotator_device = to;
            if let r @ Response::Error { .. } = rewrite_item(&mut v, it) {
                return r;
            }
        }
        Response::Ok
    }

    fn update_policy(
        &self,
        session: &Session,
        id: ItemId,
        policy: warden_core::RotationPolicy,
    ) -> Response {
        let u = match self.require() {
            Ok(u) => u,
            Err(r) => return r,
        };
        let mut v = lock(&u.vault);
        let Some(mut item) = v.get(&id).cloned() else {
            return error("not_found", format!("item {id}"));
        };
        if policy.interval.is_some_and(|d| d.is_zero()) {
            return error(
                "bad_request",
                "the rotation interval must be longer than zero",
            );
        }
        let full = session.capabilities().contains(&Capability::Full);
        if !full {
            let default_interval = lock(&self.settings).default_interval;
            if let Some(msg) = weakens_policy(&item.policy, &policy, default_interval) {
                return error("needs_confirmation", msg);
            }
        }
        item.policy = policy;
        rewrite_item(&mut v, item)
    }

    fn update_item(
        &self,
        id: ItemId,
        name: Option<String>,
        sinks: Option<Vec<warden_core::SinkSpec>>,
        mcp: Option<warden_core::McpPolicy>,
        tags: Option<Vec<String>>,
    ) -> Response {
        let u = match self.require() {
            Ok(u) => u,
            Err(r) => return r,
        };
        if let Some(list) = &sinks {
            for spec in list {
                if let Err(e) = warden_sinks::build(spec) {
                    return error("bad_request", format!("invalid sink: {e}"));
                }
            }
        }
        let mut v = lock(&u.vault);
        let Some(mut item) = v.get(&id).cloned() else {
            return error("not_found", format!("item {id}"));
        };
        if let Some(n) = name {
            if n.trim().is_empty() {
                return error("bad_request", "name is empty");
            }
            if v.items()
                .iter()
                .any(|i| i.id != id && i.name.eq_ignore_ascii_case(&n))
            {
                return error("conflict", "an item with this name exists");
            }
            item.name = n;
        }
        if let Some(s) = sinks {
            item.sinks = s;
        }
        if let Some(m) = mcp {
            item.mcp = m;
        }
        if let Some(t) = tags {
            item.tags = t;
        }
        rewrite_item(&mut v, item)
    }

    fn sign_pledge(&self, user: &str) -> Response {
        let user = user.trim();
        if user.is_empty() || user.chars().count() > 128 {
            return error("bad_request", "user must have 1 to 128 characters");
        }
        let _g = lock(&self.coffee_lock);
        let store = CoffeeStore::new(self.paths.settings_file());
        let mut st = match store.load() {
            Ok(st) => st,
            Err(e) => return error("internal", e.to_string()),
        };
        if warden_coffee::is_pledged(&st) {
            return Response::Ok;
        }
        warden_coffee::sign_pledge(&mut st, user, self.clock.as_ref());
        match store.save(&st) {
            Ok(()) => Response::Ok,
            Err(e) => error("internal", e.to_string()),
        }
    }

    fn list_clients(&self) -> Response {
        match PairingFile::new(self.paths.pairing_file()).list() {
            Ok(clients) => Response::Clients { clients },
            Err(e) => err_resp(&e),
        }
    }

    fn unpair(&self, id: &str) -> Response {
        let id = id.trim();
        if id.len() < 8 {
            return error("bad_request", "client id needs at least 8 characters");
        }
        let file = PairingFile::new(self.paths.pairing_file());
        let clients = match file.list() {
            Ok(c) => c,
            Err(e) => return err_resp(&e),
        };
        let mut hits = clients.iter().filter(|c| c.id.starts_with(id));
        let (Some(c), None) = (hits.next(), hits.next()) else {
            return if clients.iter().any(|c| c.id.starts_with(id)) {
                error("bad_request", "client id is not unique")
            } else {
                error("not_found", format!("client {id}"))
            };
        };
        if c.capabilities.contains(&Capability::Full) {
            return error("forbidden", "a Full client cannot be unpaired");
        }
        match file.remove(&c.id) {
            Ok(true) => Response::Ok,
            Ok(false) => error("not_found", format!("client {id}")),
            Err(e) => err_resp(&e),
        }
    }

    fn list_devices(&self) -> Response {
        let u = match self.require() {
            Ok(u) => u,
            Err(r) => return r,
        };
        let v = lock(&u.vault);
        let mut seen: std::collections::HashMap<DeviceId, chrono::DateTime<Utc>> =
            Default::default();
        for r in v.audit() {
            let e = seen.entry(r.device_id).or_insert(r.at);
            if r.at > *e {
                *e = r.at;
            }
        }
        let items = v.items();
        let devices = v
            .devices()
            .iter()
            .map(|d| DeviceInfo {
                id: d.id,
                name: d.name.clone(),
                is_rotator_for: items.iter().filter(|i| i.rotator_device == d.id).count() as u32,
                last_seen: seen.get(&d.id).copied(),
            })
            .collect();
        Response::Devices { devices }
    }

    async fn rotate(&self, session: &Session, id: ItemId) -> Response {
        let u = match self.require() {
            Ok(u) => u,
            Err(r) => return r,
        };
        let source = if session.capabilities().contains(&Capability::Full) {
            RotationSource::Cli
        } else {
            RotationSource::Mcp
        };
        match u.engine.request_rotation(id, source).await {
            Ok(RotationRequestOutcome::Rotated(r)) if r.complete => Response::Ok,
            Ok(RotationRequestOutcome::Rotated(r)) => {
                let failed: Vec<String> = r
                    .sinks
                    .iter()
                    .filter(|s| !s.ok)
                    .map(|s| format!("{}: {}", s.sink, s.error.as_deref().unwrap_or("failed")))
                    .collect();
                error(
                    "sinks_incomplete",
                    format!(
                        "new token is stored, but a sink failed (retry runs later): {}",
                        failed.join("; ")
                    ),
                )
            }
            Ok(RotationRequestOutcome::NeedsConfirmation) => error(
                "needs_confirmation",
                "this item needs confirmation in the desktop app",
            ),
            Ok(RotationRequestOutcome::RateLimited { retry_at }) => error(
                "rate_limited",
                format!("rotation is limited to one per hour; retry at {retry_at}"),
            ),
            Err(e) => err_resp(&e),
        }
    }

    async fn mcp_http(&self, item: ItemId, call: HttpCall) -> Response {
        let u = match self.require() {
            Ok(u) => u,
            Err(r) => return r,
        };
        let found = {
            let v = lock(&u.vault);
            v.get(&item)
                .map(|i| i.mcp.clone())
                .map(|p| v.secret(&item, TOKEN_SECRET).map(|s| (p, s)))
        };
        let (policy, secret) = match found {
            None => return error("not_found", format!("item {item}")),
            Some(Err(e)) => return err_resp(&e),
            Some(Ok(x)) => x,
        };
        let host = url_host(&call.url);
        self.local_audit("mcp_http", &format!("{item} {} {host}", call.method));
        match proxy::execute(&policy, &secret, call).await {
            Ok(r) => Response::McpHttpResponse {
                status: r.status,
                headers: r.headers,
                body: r.body,
            },
            Err(WardenError::Config(m)) => error("forbidden", m),
            Err(e) => err_resp(&e),
        }
    }

    fn audit(&self, item: Option<ItemId>, limit: u32) -> Response {
        let u = match self.require() {
            Ok(u) => u,
            Err(r) => return r,
        };
        let records = lock(&u.vault).audit();
        let mut out: Vec<AuditEntry> = records
            .into_iter()
            .filter(|r| item.is_none_or(|i| r.item_id == i))
            .map(|r| AuditEntry {
                at: r.at,
                device: r.device_id,
                item: Some(r.item_id),
                action: match r.action {
                    AuditAction::Put => "put".into(),
                    AuditAction::Delete => "delete".into(),
                },
                detail: format!(
                    "{} on {}",
                    r.item_name.unwrap_or_else(|| r.item_id.to_string()),
                    r.device_name
                ),
            })
            .collect();
        if item.is_none() {
            out.extend(self.read_local_audit());
            out.sort_by_key(|e| e.at);
        }
        let keep = limit as usize;
        if out.len() > keep {
            out.drain(..out.len() - keep);
        }
        Response::Audit { audit: out }
    }

    fn pair(&self, name: String, caps: Vec<Capability>) -> Response {
        if name.trim().is_empty() || caps.is_empty() {
            return error("bad_request", "name and capabilities are required");
        }
        if caps.contains(&Capability::Full) {
            return error("forbidden", "the Full capability cannot be paired this way");
        }
        match PairingFile::new(self.paths.pairing_file()).add(&name, &caps) {
            Ok(t) => Response::Paired {
                capabilities: caps,
                token: t.secret().clone(),
            },
            Err(e) => err_resp(&e),
        }
    }

    fn set_settings(&self, s: Settings) -> Response {
        if s.default_interval.is_zero() {
            return error("bad_request", "default interval must be more than 0");
        }
        if s.quick_unlock && !s.keychain_cache {
            return error("bad_request", "quick unlock needs the keychain cache");
        }
        if let Err(e) = store::save_settings(&self.paths, &s) {
            return err_resp(&e);
        }
        let was_quick = self.settings().quick_unlock;
        *lock(&self.settings) = s;
        // Quick unlock off while soft locked: lock behaves as before, so remove the key.
        if was_quick && !s.quick_unlock && self.paths.soft_lock_file().exists() {
            self.forget_cached_key();
        }
        if let Some(u) = self.current() {
            u.engine.set_settings(s);
        }
        Response::Ok
    }

    fn coffee_state(&self) -> warden_coffee::CoffeeState {
        CoffeeStore::new(self.paths.settings_file())
            .load()
            .unwrap_or_default()
    }

    /// Mark the current year as paid (honor system) and return the coffee state.
    fn coffee_mark_paid(&self) -> Response {
        {
            let _g = lock(&self.coffee_lock);
            let store = CoffeeStore::new(self.paths.settings_file());
            let mut st = store.load().unwrap_or_default();
            warden_coffee::mark_paid(&mut st, self.clock.as_ref());
            if let Err(e) = store.save(&st) {
                return error("internal", e.to_string());
            }
        }
        Response::Coffee(self.coffee_info())
    }

    /// Show the weekly coffee note as a desktop notification when it is due.
    async fn coffee_note(&self) {
        let reminder = self.settings().coffee_reminder;
        let note = coffee_take(&self.paths, &self.coffee_lock, |st| {
            warden_coffee::take_note(
                st,
                warden_coffee::Moment::Weekly,
                reminder,
                self.clock.as_ref(),
            )
        });
        if let Some(n) = note {
            notify(self.notify_enabled, n.title, n.body).await;
        }
    }

    fn coffee_info(&self) -> CoffeeInfo {
        let st = {
            let _g = lock(&self.coffee_lock);
            self.coffee_state()
        };
        let device = self
            .current()
            .map(|u| lock(&u.vault).device_id())
            .or_else(|| read_device_id(&self.paths))
            .unwrap_or(DeviceId(uuid::Uuid::nil()));
        let year = chrono::Datelike::year(&self.clock.now());
        CoffeeInfo {
            paid_year: st.paid_year.filter(|_| st.is_paid(self.clock.as_ref())),
            reminder_due: warden_coffee::should_show_note(
                &st,
                self.settings().coffee_reminder,
                self.clock.as_ref(),
            ),
            link: warden_coffee::COFFEE_URL.to_owned(),
            pledged: warden_coffee::is_pledged(&st),
            ticket: warden_coffee::ticket_no(&device.to_string(), year),
            price_label: warden_coffee::PRICE_LABEL.into(),
        }
    }

    async fn inbox_accept(&self, id: warden_core::InboxId, draft: ItemDraft) -> Response {
        let u = match self.require() {
            Ok(u) => u,
            Err(r) => return r,
        };
        let key = *lock(&u.vault).export_vault_key();
        let value = match self.inbox.open(&key, id) {
            Ok(v) => v,
            Err(e) => return err_resp(&e),
        };
        let r = self.add_item(draft, value).await;
        // The item is stored in both cases, so the entry goes.
        let stored = match &r {
            Response::Added { .. } => true,
            Response::Error { code, .. } => code == "sinks_incomplete",
            _ => false,
        };
        if stored && let Err(e) = self.inbox.remove(id) {
            return err_resp(&e);
        }
        r
    }

    fn inbox_add(
        &self,
        origin: String,
        label: String,
        value: SecretValue,
        provider_hint: Option<String>,
        expires_at: Option<chrono::DateTime<Utc>>,
    ) -> Response {
        let u = match self.require() {
            Ok(u) => u,
            Err(r) => return r,
        };
        let key = *lock(&u.vault).export_vault_key();
        let meta = NewInbox {
            origin,
            label,
            provider_hint,
            expires_at,
        };
        match self.inbox.add(&key, meta, &value) {
            Ok(id) => Response::InboxAdded { id },
            Err(e) => err_resp(&e),
        }
    }

    fn status(&self) -> Response {
        let (locked, device, count) = match self.current() {
            Some(u) => {
                let v = lock(&u.vault);
                (false, v.device_id(), v.items().len())
            }
            None => (
                true,
                read_device_id(&self.paths).unwrap_or(DeviceId(uuid::Uuid::nil())),
                0,
            ),
        };
        Response::Status(StatusInfo {
            version: env!("CARGO_PKG_VERSION").into(),
            locked,
            device_id: device,
            item_count: count,
            inbox_count: self.inbox.count(),
        })
    }

    /// One pass of the background loop: vault reload, scheduler tick.
    async fn background_pass(&self) {
        let Some(u) = self.current() else { return };
        let v = Arc::clone(&u.vault);
        let reloaded = tokio::task::spawn_blocking(move || lock(&v).reload()).await;
        match reloaded {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::warn!("vault reload failed, scheduler pass skipped: {e}");
                return;
            }
            Err(e) => {
                tracing::warn!("reload task failed: {e}");
                return;
            }
        }
        if let Err(e) = u.engine.tick().await {
            tracing::warn!("scheduler pass failed: {e}");
        }
    }
}

#[async_trait]
impl Handler for Daemon {
    async fn handle(&self, session: &Session, req: Request) -> Response {
        match req {
            Request::Status => self.status(),
            Request::ListItems => match self.require() {
                Err(r) => r,
                Ok(u) => {
                    let s = self.settings();
                    let v = lock(&u.vault);
                    Response::Items {
                        items: v
                            .items()
                            .into_iter()
                            .map(|i| self.summary(i, &s, &u.engine))
                            .collect(),
                    }
                }
            },
            Request::GetItem { item } => match self.require() {
                Err(r) => r,
                Ok(u) => match lock(&u.vault).get(&item) {
                    Some(i) if session.capabilities().contains(&Capability::Full) => {
                        Response::Item(Box::new(i.clone()))
                    }
                    // Other clients get no sink paths, hosts or key file paths.
                    Some(i) => Response::Item(Box::new(Item {
                        sinks: Vec::new(),
                        ..i.clone()
                    })),
                    None => error("not_found", format!("item {item}")),
                },
            },
            Request::AddItem { draft, secret } => self.add_item(draft, secret).await,
            Request::CreateDerived { draft } => self.create_derived(draft).await,
            Request::Handover { item, to } => self.handover(item, to),
            Request::UpdatePolicy { item, policy } => self.update_policy(session, item, policy),
            Request::UpdateItem {
                item,
                name,
                sinks,
                mcp,
                tags,
            } => self.update_item(item, name, sinks, mcp, tags),
            Request::SignPledge { user } => self.sign_pledge(&user),
            Request::ListClients => self.list_clients(),
            Request::Unpair { id } => self.unpair(&id),
            Request::ListDevices => self.list_devices(),
            Request::RotateNow { item } => self.rotate(session, item).await,
            Request::DeleteItem { item } => self.delete_item(item),
            Request::Unlock {
                password,
                secret_key,
            } => self.unlock(password, secret_key).await,
            Request::Lock => self.lock_vault(false),
            Request::LockForget => self.lock_vault(true),
            Request::UnlockQuick => self.unlock_quick().await,
            Request::InboxList => match self.inbox.list() {
                Ok(inbox) => Response::Inbox { inbox },
                Err(e) => err_resp(&e),
            },
            Request::InboxAdd {
                origin,
                label,
                value,
                provider_hint,
                expires_at,
            } => {
                // An MCP client cannot claim a browser origin.
                let mcp = session
                    .capabilities()
                    .iter()
                    .any(|c| matches!(c, Capability::McpUse | Capability::McpAdmin));
                let origin = if mcp { format!("mcp:{origin}") } else { origin };
                self.inbox_add(origin, label, value, provider_hint, expires_at)
            }
            Request::InboxAccept { id, draft } => self.inbox_accept(id, draft).await,
            Request::InboxReject { id } => match self.inbox.remove(id) {
                Ok(true) => Response::Ok,
                Ok(false) => error("not_found", format!("inbox entry {id}")),
                Err(e) => err_resp(&e),
            },
            Request::Pair { name, capabilities } => self.pair(name, capabilities),
            Request::McpHttpRequest {
                item,
                method,
                url,
                headers,
                body,
            } => {
                self.mcp_http(
                    item,
                    HttpCall {
                        method,
                        url,
                        headers,
                        body,
                    },
                )
                .await
            }
            Request::GetSettings => Response::Settings(self.settings()),
            Request::SetSettings { settings } => self.set_settings(settings),
            Request::CoffeeStatus => Response::Coffee(self.coffee_info()),
            Request::CoffeeMarkPaid => self.coffee_mark_paid(),
            Request::AuditList { item, limit } => self.audit(item, limit),
        }
    }
}

/// Save `item` with its current secrets, so the vault writes a new version.
fn rewrite_item(v: &mut Vault, item: Item) -> Response {
    let id = item.id;
    let mut secrets = std::collections::BTreeMap::new();
    for name in v.secret_names(&id) {
        match v.secret(&id, &name) {
            Ok(s) => {
                secrets.insert(name, s);
            }
            Err(e) => return err_resp(&e),
        }
    }
    match v.put(item, secrets) {
        Ok(()) => Response::Ok,
        Err(e) => err_resp(&e),
    }
}

/// Load the coffee state, run `f`, save the state, and return the note. Never fails the caller.
fn coffee_take<T>(
    paths: &Paths,
    lk: &Mutex<()>,
    f: impl FnOnce(&mut warden_coffee::CoffeeState) -> Option<T>,
) -> Option<T> {
    let _g = lock(lk);
    let store = CoffeeStore::new(paths.settings_file());
    let mut st = store.load().unwrap_or_default();
    let r = f(&mut st);
    if let Err(e) = store.save(&st) {
        tracing::warn!("cannot save the coffee state: {e}");
        return None;
    }
    r
}

/// Text of a desktop notification for an engine event, if the event needs one.
pub fn describe_event(ev: &EngineEvent) -> Option<(String, String)> {
    match ev {
        EngineEvent::Rotated {
            name,
            complete: true,
            ..
        } => Some(("Token rotated".into(), format!("{name} has a new value."))),
        EngineEvent::Rotated { name, .. } => Some((
            "Token rotated, a place failed".into(),
            format!("{name}: a sink did not take the new value. Warden retries."),
        )),
        EngineEvent::Failed { name, error, .. } => {
            Some((format!("Rotation failed: {name}"), error.clone()))
        }
        EngineEvent::ExpiringSoon {
            name, expires_at, ..
        } => Some((
            format!("{name} expires soon"),
            format!("End date: {}. Renew it by hand.", expires_at.date_naive()),
        )),
        EngineEvent::Due { name, .. } => Some((
            format!("{name} is due"),
            "Warden does not rotate this token. Renew it by hand.".into(),
        )),
        _ => None,
    }
}

async fn notify(enabled: bool, title: String, body: String) {
    if !enabled {
        tracing::info!("notification: {title}");
        return;
    }
    let r = tokio::task::spawn_blocking(move || {
        notify_rust::Notification::new()
            .appname("Aivory Warden")
            .summary(&title)
            .body(&body)
            .show()
            .map(|_| ())
    })
    .await;
    if let Ok(Err(e)) = r {
        tracing::warn!("desktop notification failed: {e}");
    }
}

/// Run the daemon until Ctrl-C. Fails when another daemon uses the endpoint.
pub async fn run(
    paths: Paths,
    vault_override: Option<PathBuf>,
    key_file: Option<PathBuf>,
) -> Result<()> {
    std::fs::create_dir_all(&paths.config)?;
    std::fs::create_dir_all(&paths.data)?;
    let server = Server::bind(paths.endpoint().as_deref()).map_err(|e| {
        WardenError::Ipc(format!(
            "cannot start: another daemon may run on this endpoint ({e})"
        ))
    })?;
    let server = server.with_pairing_store(Arc::new(PairingFile::new(paths.pairing_file())));
    let mut daemon = Daemon::new(paths, vault_override)?;
    if let Some(p) = key_file {
        daemon = daemon.with_key_file(p);
    }
    let daemon = Arc::new(daemon);
    daemon.try_auto_unlock().await;

    let bg = Arc::clone(&daemon);
    tokio::spawn(async move {
        let mut last_note = Instant::now()
            .checked_sub(Duration::from_secs(3600))
            .unwrap_or_else(Instant::now);
        loop {
            bg.background_pass().await;
            if last_note.elapsed() >= Duration::from_secs(3600) {
                last_note = Instant::now();
                bg.coffee_note().await;
            }
            tokio::time::sleep(bg.engine_cfg.tick).await;
        }
    });

    eprintln!(
        "aivory-warden daemon listening on {}",
        server.path().display()
    );
    tokio::select! {
        r = server.serve(daemon) => r,
        _ = tokio::signal::ctrl_c() => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use warden_core::FixedClock;

    fn test_daemon(dir: &std::path::Path) -> Daemon {
        let mut d = Daemon::new(Paths::from_home(dir.to_path_buf()), None).unwrap();
        d.clock = Arc::new(FixedClock::new(
            chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 11, 24, 10, 0, 0).unwrap(),
        ));
        d
    }

    /// A daemon with a fresh vault. The OS keychain is off; a key file is the cache.
    async fn quick_daemon(dir: &std::path::Path) -> Daemon {
        let paths = Paths::from_home(dir.to_path_buf());
        let local = paths.device_dir();
        let key_file = dir.join("key");
        let (vault, sk) = Vault::create_with_params(
            &paths.default_vault(),
            "synthetic-password",
            None,
            "test",
            &local,
            warden_vault::KdfParams::new(64, 1, 1),
        )
        .unwrap();
        drop(vault);
        let mut d = test_daemon(dir).with_key_file(key_file);
        d.keychain_enabled = false;
        let r = d
            .unlock(
                SecretValue::new("synthetic-password"),
                SecretValue::new(sk.to_string()),
            )
            .await;
        assert!(matches!(r, Response::Ok));
        d
    }

    fn code(r: &Response) -> &str {
        match r {
            Response::Error { code, .. } => code,
            _ => "ok",
        }
    }

    fn quick(on: bool) -> Settings {
        Settings {
            quick_unlock: on,
            ..Settings::default()
        }
    }

    #[tokio::test]
    async fn quick_unlock_is_off_by_default_and_refused() {
        let dir = tempfile::tempdir().unwrap();
        let d = quick_daemon(dir.path()).await;
        assert!(!d.settings().quick_unlock);
        // Lock behaves as before: the key is removed.
        assert!(matches!(d.lock_vault(false), Response::Ok));
        assert!(d.current().is_none());
        assert!(!dir.path().join("key").exists());
        assert_eq!(code(&d.unlock_quick().await), "quick_unlock_off");
        assert!(d.current().is_none());
    }

    #[tokio::test]
    async fn quick_unlock_needs_the_keychain_cache() {
        let dir = tempfile::tempdir().unwrap();
        let d = quick_daemon(dir.path()).await;
        let bad = Settings {
            keychain_cache: false,
            ..quick(true)
        };
        assert_eq!(code(&d.set_settings(bad)), "bad_request");
        assert!(!d.settings().quick_unlock);
    }

    #[tokio::test]
    async fn soft_lock_keeps_the_key_and_quick_unlock_opens() {
        let dir = tempfile::tempdir().unwrap();
        let d = quick_daemon(dir.path()).await;
        assert!(matches!(d.set_settings(quick(true)), Response::Ok));
        assert!(matches!(d.lock_vault(false), Response::Ok));
        assert!(d.current().is_none());
        assert!(dir.path().join("key").exists(), "soft lock keeps the key");
        // A restart must not open a soft locked vault.
        d.try_auto_unlock().await;
        assert!(d.current().is_none());
        assert!(matches!(d.unlock_quick().await, Response::Ok));
        assert!(d.current().is_some());
        assert!(!d.paths.soft_lock_file().exists());
        let log = d.read_local_audit();
        assert!(log.iter().any(|e| e.action == "quick_unlock"));
    }

    #[tokio::test]
    async fn cancelled_or_failed_check_leaves_the_vault_locked() {
        use warden_verify::{FakeVerifier, VerifyError, gate};
        let dir = tempfile::tempdir().unwrap();
        let d = quick_daemon(dir.path()).await;
        assert!(matches!(d.set_settings(quick(true)), Response::Ok));
        d.lock_vault(false);
        for e in [
            VerifyError::Cancelled,
            VerifyError::Failed("x".into()),
            VerifyError::Unavailable("x".into()),
        ] {
            let mut sent = false;
            let r = gate(&FakeVerifier::failing(e), None, "r", || sent = true);
            assert!(r.is_err() && !sent, "no request after a failed check");
            assert!(d.current().is_none());
        }
        // A passing check lets the client send the request.
        let mut sent = false;
        gate(&FakeVerifier::passing(), None, "r", || sent = true).unwrap();
        assert!(sent);
        assert!(matches!(d.unlock_quick().await, Response::Ok));
    }

    #[tokio::test]
    async fn lock_forget_removes_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let d = quick_daemon(dir.path()).await;
        assert!(matches!(d.set_settings(quick(true)), Response::Ok));
        assert!(matches!(d.lock_vault(true), Response::Ok));
        assert!(!dir.path().join("key").exists());
        assert_eq!(code(&d.unlock_quick().await), "no_cached_key");
        assert!(d.current().is_none());
        let log = d.read_local_audit();
        assert!(log.iter().any(|e| e.action == "quick_unlock_refused"));
    }

    #[tokio::test]
    async fn quick_unlock_off_while_soft_locked_forgets_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let d = quick_daemon(dir.path()).await;
        assert!(matches!(d.set_settings(quick(true)), Response::Ok));
        d.lock_vault(false);
        assert!(matches!(d.set_settings(quick(false)), Response::Ok));
        assert!(!dir.path().join("key").exists());
        assert!(!d.paths.soft_lock_file().exists());
    }

    #[test]
    fn coffee_mark_paid_sets_the_year_and_the_info() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let info = d.coffee_info();
        assert!(info.paid_year.is_none());
        assert_eq!(info.link, warden_coffee::COFFEE_URL);
        let Response::Coffee(after) = d.coffee_mark_paid() else {
            panic!("no coffee response");
        };
        assert_eq!(after.paid_year, Some(2026));
        assert!(!after.reminder_due);
        let st = d.coffee_state();
        assert_eq!(st.paid_year, Some(2026));
        assert!(st.paid_at.is_some());
    }

    #[test]
    fn partial_client_cannot_weaken_policy() {
        use warden_core::RotationPolicy;
        let day = Duration::from_secs(24 * 3600);
        let cur = RotationPolicy {
            interval: Some(30 * day),
            ..RotationPolicy::default()
        };
        let with = |f: &dyn Fn(&mut RotationPolicy)| {
            let mut p = cur;
            f(&mut p);
            weakens_policy(&cur, &p, 90 * day)
        };
        assert!(with(&|p| p.auto_rotate = false).is_some());
        assert!(
            with(&|p| p.interval = Some(Duration::from_secs(u32::MAX as u64 * 86400))).is_some()
        );
        assert!(with(&|p| p.interval = Some(31 * day)).is_some());
        assert!(with(&|p| p.interval = None).is_some()); // default 90 d is longer
        assert!(with(&|p| p.lead_time = Duration::ZERO).is_some());
        assert!(with(&|p| p.interval = Some(7 * day)).is_none());
        assert!(with(&|p| p.lead_time = 5 * day).is_none());
        assert!(with(&|p| p.grace = cur.grace + day).is_some());
        assert!(with(&|p| p.grace = Duration::ZERO).is_none());
        // A value above 365 days is refused even when the current one is longer.
        let long = RotationPolicy {
            interval: Some(500 * day),
            ..RotationPolicy::default()
        };
        let mut p = long;
        p.interval = Some(400 * day);
        assert!(weakens_policy(&long, &p, 90 * day).is_some());
    }

    #[test]
    fn slug_rules() {
        assert!(valid_slug("gitlab-ci_1"));
        assert!(!valid_slug(""));
        assert!(!valid_slug("Bad Slug"));
    }

    #[test]
    fn events_map_to_notifications() {
        let ev = EngineEvent::Failed {
            item_id: ItemId::new(),
            name: "n".into(),
            error: "boom".into(),
            next_retry: None,
        };
        let (t, b) = describe_event(&ev).unwrap();
        assert!(t.contains("failed") && b == "boom");
        assert!(describe_event(&EngineEvent::Locked).is_none());
    }

    #[test]
    fn errors_map_to_codes() {
        let Response::Error { code, .. } = err_resp(&WardenError::Locked) else {
            panic!("no error");
        };
        assert_eq!(code, "locked");
    }
}
