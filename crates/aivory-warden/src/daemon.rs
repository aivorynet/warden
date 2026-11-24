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
    AuditEntry, Capability, CoffeeInfo, ItemDraft, ItemSummary, Request, Response, StatusInfo,
};
use warden_core::{
    Clock, DeviceId, Item, ItemId, ItemKind, Result, SecretValue, Settings, SystemClock,
    WardenError, next_rotation,
};
use warden_engine::{
    Engine, EngineConfig, EngineEvent, ProviderFactory, RotationRequestOutcome, RotationSource,
    SinkFactory, TOKEN_SECRET,
};
use warden_ipc::{Handler, Server, Session};
use warden_mcp::proxy::{self, HttpCall};
use warden_vault::{AuditAction, SecretKey, Vault, keychain};

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
            notify_enabled: !flag("WARDEN_NO_NOTIFY"),
            coffee_lock: Arc::new(Mutex::new(())),
        })
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
        if !self.keychain_enabled {
            return;
        }
        let Ok(dir) = self.vault_dir() else { return };
        let Some(vid) = vault_id_of(&dir) else { return };
        let key = match keychain::load(&vid) {
            Ok(Some(k)) => k,
            Ok(None) => return,
            Err(e) => {
                tracing::warn!("keychain read failed: {e}");
                return;
            }
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

    async fn install(&self, vault: Vault, cache_key: bool) -> Result<()> {
        let device = vault.device_id();
        if cache_key && self.keychain_enabled {
            let key = vault.export_vault_key();
            if let Err(e) = keychain::store(&vault.vault_id(), &key) {
                tracing::warn!("cannot cache the key in the keychain: {e}");
            }
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

    fn lock_vault(&self) -> Response {
        let taken = lock(&self.unlocked).take();
        if let Some(u) = &taken {
            u.engine.set_locked(true);
        }
        // A locked daemon stays locked after a restart, so remove the cached key.
        if self.keychain_enabled
            && let Ok(dir) = self.vault_dir()
            && let Some(vid) = vault_id_of(&dir)
            && let Err(e) = keychain::clear(&vid)
        {
            tracing::warn!("cannot clear the keychain entry: {e}");
        }
        Response::Ok
    }

    fn summary(&self, item: &Item, settings: &Settings) -> ItemSummary {
        ItemSummary {
            id: item.id,
            name: item.name.clone(),
            provider: item.provider.kind,
            kind: item.kind,
            expires_at: item.expires_at,
            next_rotation: next_rotation(item, settings, self.clock.now()),
            sink_count: item.sinks.len(),
            auto_rotate: item.policy.auto_rotate,
        }
    }

    fn add_item(&self, draft: ItemDraft, secret: SecretValue) -> Response {
        let u = match self.require() {
            Ok(u) => u,
            Err(r) => return r,
        };
        if draft.name.trim().is_empty() {
            return error("bad_request", "name is empty");
        }
        if !valid_slug(&draft.slug) {
            return error(
                "bad_request",
                "slug must have 1 to 40 characters from a-z, 0-9, - and _",
            );
        }
        let mut v = lock(&u.vault);
        if v.items()
            .iter()
            .any(|i| i.name.eq_ignore_ascii_case(&draft.name) || i.slug == draft.slug)
        {
            return error("conflict", "an item with this name or slug exists");
        }
        if let ItemKind::Derived { parent } = draft.kind
            && v.get(&parent).is_none_or(|p| p.kind != ItemKind::Admin)
        {
            return error("bad_request", "parent must be an existing admin item");
        }
        let item = Item {
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
        };
        let id = item.id;
        let secrets = [(TOKEN_SECRET.to_owned(), secret)].into_iter().collect();
        match v.put(item, secrets) {
            Ok(()) => Response::Added { item: id },
            Err(e) => err_resp(&e),
        }
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
        let full = session.capabilities().contains(&Capability::Full);
        if !full && item.policy.auto_rotate && !policy.auto_rotate {
            return error(
                "needs_confirmation",
                "turning rotation off needs confirmation in the desktop app",
            );
        }
        item.policy = policy;
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
        let keep = limit as usize;
        if out.len() > keep {
            out.drain(..out.len() - keep);
        }
        Response::Audit { audit: out }
    }

    fn pair(&self, session: &Session, name: String, caps: Vec<Capability>) -> Response {
        if session.is_bootstrap() {
            return error("forbidden", "pairing needs a Full client");
        }
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
        if let Err(e) = store::save_settings(&self.paths, &s) {
            return err_resp(&e);
        }
        *lock(&self.settings) = s;
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

    fn coffee_receipt(&self, code: &str) -> Response {
        let store = CoffeeStore::new(self.paths.settings_file());
        let mut st = self.coffee_state();
        match warden_coffee::apply_receipt(&mut st, code.trim(), self.clock.as_ref()) {
            Ok(_) => match store.save(&st) {
                Ok(()) => Response::Ok,
                Err(e) => error("internal", e.to_string()),
            },
            Err(e) => error("bad_request", e.to_string()),
        }
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
        let st = self.coffee_state();
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
            link: warden_coffee::COFFEE_URL.into(),
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
        let r = self.add_item(draft, value);
        if matches!(r, Response::Added { .. })
            && let Err(e) = self.inbox.remove(id)
        {
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
                        items: v.items().into_iter().map(|i| self.summary(i, &s)).collect(),
                    }
                }
            },
            Request::GetItem { item } => match self.require() {
                Err(r) => r,
                Ok(u) => match lock(&u.vault).get(&item) {
                    Some(i) => Response::Item(Box::new(i.clone())),
                    None => error("not_found", format!("item {item}")),
                },
            },
            Request::AddItem { draft, secret } => self.add_item(draft, secret),
            Request::UpdatePolicy { item, policy } => self.update_policy(session, item, policy),
            Request::RotateNow { item } => self.rotate(session, item).await,
            Request::DeleteItem { item } => match self.require() {
                Err(r) => r,
                Ok(u) => match lock(&u.vault).delete(&item) {
                    Ok(()) => Response::Ok,
                    Err(e) => err_resp(&e),
                },
            },
            Request::Unlock {
                password,
                secret_key,
            } => self.unlock(password, secret_key).await,
            Request::Lock => self.lock_vault(),
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
            } => self.inbox_add(origin, label, value, provider_hint, expires_at),
            Request::InboxAccept { id, draft } => self.inbox_accept(id, draft).await,
            Request::InboxReject { id } => match self.inbox.remove(id) {
                Ok(true) => Response::Ok,
                Ok(false) => error("not_found", format!("inbox entry {id}")),
                Err(e) => err_resp(&e),
            },
            Request::Pair { name, capabilities } => self.pair(session, name, capabilities),
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
            Request::CoffeeReceipt { code } => self.coffee_receipt(&code),
            Request::AuditList { item, limit } => self.audit(item, limit),
        }
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
pub async fn run(paths: Paths, vault_override: Option<PathBuf>) -> Result<()> {
    std::fs::create_dir_all(&paths.config)?;
    std::fs::create_dir_all(&paths.data)?;
    let server = Server::bind(paths.endpoint().as_deref()).map_err(|e| {
        WardenError::Ipc(format!(
            "cannot start: another daemon may run on this endpoint ({e})"
        ))
    })?;
    let server = server.with_pairing_store(Arc::new(PairingFile::new(paths.pairing_file())));
    let daemon = Arc::new(Daemon::new(paths, vault_override)?);
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
