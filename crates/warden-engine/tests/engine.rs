//! Engine tests: fake provider, fake sinks, real vault (fast KDF), fixed clock.

use async_trait::async_trait;
use chrono::{DateTime, Duration as CDuration, TimeZone, Utc};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use warden_core::{
    Clock, CreateRequest, DeviceId, FixedClock, IssuedToken, Item, ItemId, ItemKind, McpPolicy,
    Provider, ProviderCaps, ProviderKind, ProviderRef, Result, RotateRequest, RotationClass,
    RotationPolicy, SecretValue, Settings, Sink, SinkSpec, TokenInfo, WardenError,
};
use warden_engine::{
    Engine, EngineConfig, EngineEvent, ItemStatus, RevokeState, RotationRequestOutcome,
    RotationSource,
};
use warden_vault::{KdfParams, Vault};

// ---------- fakes ----------

#[derive(Default)]
struct Inner {
    counter: u32,
    valid: HashMap<String, String>, // value -> provider token id
    calls: u32,
    limit: Option<Option<Duration>>,
    /// Error text for `issue`, and whether the provider acts before it fails.
    issue_fail: Option<(String, bool)>,
    revoke_404: bool,
    /// When set, every issued token gets this id (Cloudflare roll keeps the id).
    fixed_id: Option<String>,
    /// Message of the `ProviderAuth` error for a dead credential.
    auth_msg: Option<String>,
    /// Token id that `verify` returns (default `x`).
    verify_id: Option<String>,
}

#[derive(Default)]
struct Fake(Mutex<Inner>);

impl Fake {
    fn add_valid(&self, value: &str, id: &str) {
        self.0.lock().unwrap().valid.insert(value.into(), id.into());
    }
    fn is_valid(&self, value: &str) -> bool {
        self.0.lock().unwrap().valid.contains_key(value)
    }
    fn calls(&self) -> u32 {
        self.0.lock().unwrap().calls
    }
    fn set_issue_fail(&self, f: Option<(&str, bool)>) {
        self.0.lock().unwrap().issue_fail = f.map(|(m, a)| (m.to_owned(), a));
    }
    fn set_revoke_404(&self, on: bool) {
        self.0.lock().unwrap().revoke_404 = on;
    }
    fn set_limit(&self, l: Option<Option<Duration>>) {
        self.0.lock().unwrap().limit = l;
    }
}

struct FakeProvider {
    fake: Arc<Fake>,
    class: RotationClass,
}

impl FakeProvider {
    fn enter(&self, cred: &SecretValue) -> Result<()> {
        let g = self.fake.0.lock().unwrap();
        drop(g);
        let mut g = self.fake.0.lock().unwrap();
        g.calls += 1;
        if let Some(l) = g.limit {
            return Err(WardenError::ProviderRateLimited { retry_after: l });
        }
        if !g.valid.contains_key(cred.expose()) {
            return Err(WardenError::ProviderAuth(
                g.auth_msg
                    .clone()
                    .unwrap_or_else(|| "HTTP 401: dead credential".into()),
            ));
        }
        Ok(())
    }
    fn issue_checked(&self, cred: &SecretValue) -> Result<IssuedToken> {
        self.enter(cred)?;
        let fail = self.fake.0.lock().unwrap().issue_fail.clone();
        let Some((msg, acted)) = fail else {
            return Ok(self.issue());
        };
        if acted {
            let _ = self.issue();
            if self.class == RotationClass::AtomicSwap {
                self.fake.0.lock().unwrap().valid.remove(cred.expose());
            }
        }
        Err(WardenError::Provider(msg))
    }
    fn issue(&self) -> IssuedToken {
        let mut g = self.fake.0.lock().unwrap();
        g.counter += 1;
        let id = g.fixed_id.clone().unwrap_or(format!("id-{}", g.counter));
        let v = format!("tok-{}", g.counter);
        g.valid.insert(v.clone(), id.clone());
        IssuedToken {
            value: SecretValue::new(v),
            provider_token_id: id,
            expires_at: None,
        }
    }
}

#[async_trait]
impl Provider for FakeProvider {
    fn class(&self) -> RotationClass {
        self.class
    }
    fn capabilities(&self) -> ProviderCaps {
        ProviderCaps {
            self_rotate: true,
            create_derived: true,
            revoke: true,
            naming: true,
        }
    }
    async fn verify(&self, cred: &SecretValue) -> Result<TokenInfo> {
        self.enter(cred)?;
        let vid = self.fake.0.lock().unwrap().verify_id.clone();
        Ok(TokenInfo {
            provider_token_id: vid.unwrap_or_else(|| "x".into()),
            expires_at: None,
            scopes: vec![],
        })
    }
    async fn rotate_self(&self, cred: &SecretValue, req: &RotateRequest) -> Result<IssuedToken> {
        assert!(req.token_name.starts_with("aivw_"));
        let t = self.issue_checked(cred)?;
        if self.class == RotationClass::AtomicSwap {
            self.fake.0.lock().unwrap().valid.remove(cred.expose());
        }
        Ok(t)
    }
    async fn create_derived(&self, admin: &SecretValue, _: &CreateRequest) -> Result<IssuedToken> {
        self.issue_checked(admin)
    }
    async fn revoke(&self, admin: &SecretValue, id: &str) -> Result<()> {
        self.enter(admin)?;
        if self.fake.0.lock().unwrap().revoke_404 {
            return Err(WardenError::Provider("HTTP 404: no such token".into()));
        }
        self.fake.0.lock().unwrap().valid.retain(|_, v| v != id);
        Ok(())
    }
}

#[derive(Default)]
struct SinkWorld {
    values: Mutex<HashMap<String, String>>,
    failing: Mutex<HashSet<String>>,
}

struct FakeSink {
    world: Arc<SinkWorld>,
    key: String,
}

#[async_trait]
impl Sink for FakeSink {
    async fn write(&self, v: &SecretValue) -> Result<()> {
        if self.world.failing.lock().unwrap().contains(&self.key) {
            return Err(WardenError::Sink("disk full".into()));
        }
        self.world
            .values
            .lock()
            .unwrap()
            .insert(self.key.clone(), v.expose().into());
        Ok(())
    }
    async fn read_back_matches(&self, v: &SecretValue) -> Result<bool> {
        Ok(self
            .world
            .values
            .lock()
            .unwrap()
            .get(&self.key)
            .map(String::as_str)
            == Some(v.expose()))
    }
    fn describe(&self) -> String {
        format!("fake sink {}", self.key)
    }
}

// ---------- harness ----------

struct Env {
    _tmp: tempfile::TempDir,
    vault: Arc<Mutex<Vault>>,
    clock: Arc<FixedClock>,
    fake: Arc<Fake>,
    sinks: Arc<SinkWorld>,
    device: DeviceId,
    journal: std::path::PathBuf,
}

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 24, 12, 0, 0).unwrap()
}

impl Env {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let clock = Arc::new(FixedClock::new(t0()));
        let (v, _) = Vault::create_with_params(
            &tmp.path().join("vault"),
            "pw",
            None,
            "dev",
            &tmp.path().join("local"),
            KdfParams::new(8, 1, 1),
        )
        .unwrap();
        let v = v.with_clock(clock.clone());
        let device = v.device_id();
        Self {
            journal: tmp.path().join("journal"),
            _tmp: tmp,
            vault: Arc::new(Mutex::new(v)),
            clock,
            fake: Arc::new(Fake::default()),
            sinks: Arc::new(SinkWorld::default()),
            device,
        }
    }

    fn engine_with(&self, device: DeviceId, cfg: EngineConfig) -> Engine {
        let fake = self.fake.clone();
        let world = self.sinks.clone();
        Engine::with_config(
            self.vault.clone(),
            Arc::new(move |r: &ProviderRef| {
                let class = if r.config["class"] == "atomic" {
                    RotationClass::AtomicSwap
                } else {
                    RotationClass::Overlap
                };
                Ok(Box::new(FakeProvider {
                    fake: fake.clone(),
                    class,
                }) as Box<dyn Provider>)
            }),
            Arc::new(move |s: &SinkSpec| match s {
                SinkSpec::Dotenv { key, .. } => Ok(Box::new(FakeSink {
                    world: world.clone(),
                    key: key.clone(),
                }) as Box<dyn Sink>),
                _ => Err(WardenError::Config("unsupported".into())),
            }),
            Settings::default(),
            self.clock.clone(),
            &self.journal,
            device,
            cfg,
        )
        .unwrap()
    }

    fn engine(&self) -> Engine {
        self.engine_with(
            self.device,
            EngineConfig {
                jitter: 0.0,
                ..EngineConfig::default()
            },
        )
    }

    /// Add an admin item (token `adm-<name>`) with `n` sinks.
    fn admin(&self, name: &str, atomic: bool, n: usize, policy: RotationPolicy) -> ItemId {
        let tok = format!("adm-{name}");
        self.fake.add_valid(&tok, &format!("id-{name}"));
        self.put_item(name, ItemKind::Admin, atomic, n, policy, &tok, self.device)
    }

    fn derived(&self, name: &str, parent: ItemId, atomic: bool, n: usize) -> ItemId {
        let tok = format!("der-{name}");
        self.fake.add_valid(&tok, &format!("id-{name}"));
        self.put_item(
            name,
            ItemKind::Derived { parent },
            atomic,
            n,
            policy(3600),
            &tok,
            self.device,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn put_item(
        &self,
        name: &str,
        kind: ItemKind,
        atomic: bool,
        n: usize,
        policy: RotationPolicy,
        tok: &str,
        device: DeviceId,
    ) -> ItemId {
        let id = ItemId::new();
        let sinks: Vec<SinkSpec> = (0..n)
            .map(|i| SinkSpec::Dotenv {
                path: "x.env".into(),
                key: format!("{name}-{i}"),
            })
            .collect();
        for s in &sinks {
            if let SinkSpec::Dotenv { key, .. } = s {
                self.sinks
                    .values
                    .lock()
                    .unwrap()
                    .insert(key.clone(), tok.into());
            }
        }
        let item = Item {
            id,
            name: name.into(),
            slug: name.into(),
            kind,
            provider: ProviderRef {
                kind: ProviderKind::Command,
                config: serde_json::json!({ "class": if atomic { "atomic" } else { "overlap" } }),
            },
            provider_token_id: Some(format!("id-{name}")),
            expires_at: None,
            created_at: t0(),
            rotated_at: None,
            policy,
            sinks,
            mcp: McpPolicy::default(),
            rotator_device: device,
            tags: vec![],
        };
        self.vault
            .lock()
            .unwrap()
            .put(item, [("token".to_owned(), SecretValue::new(tok))].into())
            .unwrap();
        id
    }

    fn vault_value(&self, id: ItemId) -> String {
        self.vault
            .lock()
            .unwrap()
            .secret(&id, "token")
            .unwrap()
            .expose()
            .to_owned()
    }

    fn vault_item(&self, id: ItemId) -> Item {
        self.vault.lock().unwrap().get(&id).unwrap().clone()
    }

    fn sink_values(&self, id: ItemId) -> Vec<String> {
        self.vault_item(id)
            .sinks
            .iter()
            .map(|s| match s {
                SinkSpec::Dotenv { key, .. } => self.sinks.values.lock().unwrap()[key].clone(),
                _ => unreachable!(),
            })
            .collect()
    }

    fn journal_files(&self) -> usize {
        std::fs::read_dir(&self.journal)
            .unwrap()
            .filter(|f| {
                f.as_ref()
                    .unwrap()
                    .path()
                    .extension()
                    .is_some_and(|e| e == "json")
            })
            .count()
    }

    /// Credential invariant: vault holds a value the provider accepts, and every sink
    /// holds the vault value (so no sink holds a revoked token).
    fn assert_sound(&self, id: ItemId) {
        let v = self.vault_value(id);
        assert!(self.fake.is_valid(&v), "vault value {v} is not accepted");
        for s in self.sink_values(id) {
            assert!(self.fake.is_valid(&s), "sink holds revoked token {s}");
            assert_eq!(s, v, "sink differs from vault");
        }
    }
}

fn policy(grace_s: u64) -> RotationPolicy {
    RotationPolicy {
        grace: Duration::from_secs(grace_s),
        ..RotationPolicy::default()
    }
}

// ---------- rotation flows ----------

#[tokio::test]
async fn overlap_flow_revokes_after_grace() {
    let e = Env::new();
    let id = e.admin("a", false, 2, policy(3600));
    let eng = e.engine();
    let mut rx = eng.subscribe();
    let r = eng.rotate(id).await.unwrap();
    assert!(r.complete);
    assert!(matches!(r.revoke, RevokeState::Pending { .. }));
    assert_eq!(r.sinks.len(), 2);
    assert_eq!(e.vault_value(id), "tok-1");
    assert!(e.fake.is_valid("adm-a"), "old token lives during grace");
    assert_eq!(e.sink_values(id), ["tok-1", "tok-1"]);
    assert_eq!(e.vault_item(id).provider_token_id.as_deref(), Some("id-1"));
    assert!(e.vault_item(id).rotated_at.is_some());
    assert!(eng.run_pending_revokes().await.unwrap().is_empty());
    e.clock.advance(CDuration::hours(1));
    let rv = eng.run_pending_revokes().await.unwrap();
    assert_eq!(rv.len(), 1);
    assert!(rv[0].done);
    assert!(!e.fake.is_valid("adm-a"));
    assert!(e.fake.is_valid("tok-1"));
    assert_eq!(e.journal_files(), 0);
    let mut kinds = vec![];
    while let Ok(ev) = rx.try_recv() {
        kinds.push(match ev {
            EngineEvent::Rotated { .. } => "rotated",
            EngineEvent::RevokePending { .. } => "pending",
            _ => "other",
        });
    }
    assert_eq!(kinds, ["pending", "rotated"]);
}

#[tokio::test]
async fn derived_uses_parent_secret_and_revokes_old() {
    let e = Env::new();
    let p = e.admin("p", false, 0, policy(0));
    let d = e.derived("d", p, false, 1);
    let eng = e.engine();
    eng.rotate(d).await.unwrap();
    e.clock.advance(CDuration::hours(2));
    assert_eq!(e.vault_value(d), "tok-1");
    assert_eq!(e.vault_value(p), "adm-p", "parent unchanged");
    eng.run_pending_revokes().await.unwrap();
    assert!(!e.fake.is_valid("der-d"));
    e.assert_sound(d);
}

#[tokio::test]
async fn sink_failure_is_per_sink_and_retries_forward() {
    let e = Env::new();
    let id = e.admin("a", true, 2, policy(0));
    e.sinks.failing.lock().unwrap().insert("a-1".into());
    let eng = e.engine();
    let r = eng.rotate(id).await.unwrap();
    assert!(!r.complete);
    assert!(r.sinks[0].ok && !r.sinks[1].ok);
    assert_eq!(r.sinks[1].error.as_deref(), Some("sink error: disk full"));
    // Vault holds the newest valid value; the old one is dead and never restored.
    assert_eq!(e.vault_value(id), "tok-1");
    assert!(e.fake.is_valid("tok-1") && !e.fake.is_valid("adm-a"));
    let ItemStatus::Failed {
        next_retry,
        attempts,
        ..
    } = eng.status(&id)
    else {
        panic!("status must be Failed");
    };
    assert_eq!(attempts, 1);
    assert_eq!(next_retry, t0() + CDuration::seconds(60));
    // Not yet due: tick does nothing.
    let calls = e.fake.calls();
    eng.tick().await.unwrap();
    assert_eq!(e.fake.calls(), calls);
    // Fix the sink, wait out the backoff: tick completes forward.
    e.sinks.failing.lock().unwrap().clear();
    e.clock.advance(CDuration::seconds(61));
    let t = eng.tick().await.unwrap();
    assert_eq!(t.rotated, [id]);
    e.assert_sound(id);
    assert_eq!(eng.status(&id), ItemStatus::Idle);
    assert_eq!(e.journal_files(), 0);
    assert_eq!(e.fake.calls(), calls, "no second provider rotation");
}

// ---------- fault injection ----------

const POINTS: &[&str] = &[
    "intent",
    "issued",
    "sink0",
    "sink1",
    "sinks",
    "stored",
    "revoke_queued",
    "revoke_called",
];

async fn crash_case(atomic: bool, derived: bool, point: &str) {
    let e = Env::new();
    let admin = e.admin("p", atomic, 2, policy(3600));
    let id = if derived {
        e.derived("d", admin, atomic, 2)
    } else {
        admin
    };
    let eng = e.engine();
    let before = e.vault_value(id);
    eng.inject_fault(point);
    let res = eng.rotate(id).await;
    if point == "revoke_called" {
        res.expect("rotation completes");
        e.clock.advance(CDuration::hours(2));
        assert!(eng.run_pending_revokes().await.is_err() || !derived && atomic);
    }
    drop(eng); // crash
    if !atomic {
        // Overlap never leaves the vault without a valid value.
        assert!(e.fake.is_valid(&e.vault_value(id)), "overlap {point}");
    }
    let _ = before;
    let eng2 = e.engine();
    eng2.recover().await.unwrap();
    if !atomic && point == "intent" {
        // Recover keeps the Overlap intent. A manual rotation resumes it.
        eng2.rotate(id).await.unwrap();
    }
    for _ in 0..3 {
        e.clock.advance(CDuration::hours(2));
        eng2.run_pending_revokes().await.unwrap();
        eng2.tick().await.unwrap();
        e.clock.advance(CDuration::minutes(2));
    }
    let ctx = format!("atomic={atomic} derived={derived} point={point}");
    let v = e.vault_value(id);
    assert!(e.fake.is_valid(&v), "vault value dead: {ctx}");
    for s in e.sink_values(id) {
        assert!(e.fake.is_valid(&s), "sink holds revoked token: {ctx}");
    }
    assert_eq!(e.journal_files(), 0, "journal not drained: {ctx}");
    // The parent of a derived item stays valid too.
    assert!(e.fake.is_valid(&e.vault_value(admin)), "parent dead: {ctx}");
    // A later rotation still works.
    eng2.rotate(id).await.unwrap();
    e.assert_sound(id);
}

#[tokio::test]
async fn crash_after_every_step_loses_nothing() {
    for atomic in [false, true] {
        for derived in [false, true] {
            for point in POINTS {
                crash_case(atomic, derived, point).await;
            }
        }
    }
}

#[tokio::test]
async fn atomic_crash_after_issue_recovers_new_value() {
    let e = Env::new();
    let id = e.admin("a", true, 2, policy(0));
    let eng = e.engine();
    eng.inject_fault("issued");
    assert!(eng.rotate(id).await.is_err());
    // Old token is dead, vault still holds it.
    assert!(!e.fake.is_valid(&e.vault_value(id)));
    drop(eng);
    let eng2 = e.engine();
    let reps = eng2.recover().await.unwrap();
    assert_eq!(reps.len(), 1);
    e.assert_sound(id);
    assert_eq!(e.vault_value(id), "tok-1");
}

#[tokio::test]
async fn journal_never_contains_the_secret() {
    let e = Env::new();
    let id = e.admin("a", true, 1, policy(0));
    let eng = e.engine();
    eng.inject_fault("issued");
    let _ = eng.rotate(id).await;
    for f in std::fs::read_dir(&e.journal).unwrap() {
        let text = std::fs::read_to_string(f.unwrap().path()).unwrap();
        assert!(!text.contains("tok-1") && !text.contains("adm-a"));
    }
}

// ---------- rotator lease ----------

#[tokio::test]
async fn non_rotator_device_never_calls_provider() {
    let e = Env::new();
    let id = e.admin("a", false, 1, policy(0));
    let eng = e.engine_with(DeviceId::new(), EngineConfig::default());
    let err = eng.rotate(id).await.unwrap_err();
    assert!(matches!(&err, WardenError::Config(m) if m == "not the rotator device"));
    assert!(eng.request_rotation(id, RotationSource::Mcp).await.is_err());
    assert!(eng.request_rotation(id, RotationSource::Cli).await.is_err());
    e.clock.advance(CDuration::days(400));
    assert!(eng.due_items(e.clock.now()).is_empty());
    eng.tick().await.unwrap();
    eng.recover().await.unwrap();
    assert_eq!(e.fake.calls(), 0);
}

// ---------- scheduler ----------

fn cfg(jitter: f64) -> EngineConfig {
    EngineConfig {
        jitter,
        ..EngineConfig::default()
    }
}

#[tokio::test]
async fn scheduler_honours_interval_default_and_lead_time() {
    let e = Env::new();
    let eng = e.engine_with(e.device, cfg(0.0));
    let per_item = e.admin(
        "ten",
        false,
        0,
        RotationPolicy {
            interval: Some(Duration::from_secs(10 * 86_400)),
            ..RotationPolicy::default()
        },
    );
    let default = e.admin("dflt", false, 0, RotationPolicy::default());
    let off = e.admin(
        "off",
        false,
        0,
        RotationPolicy {
            auto_rotate: false,
            ..RotationPolicy::default()
        },
    );
    // expiry at +20 d with 3 d lead time: due at +17 d, before the 30 d default
    let lead = e.admin("lead", false, 0, RotationPolicy::default());
    {
        let mut v = e.vault.lock().unwrap();
        let mut it = v.get(&lead).unwrap().clone();
        it.expires_at = Some(t0() + CDuration::days(20));
        let tok = v.secret(&lead, "token").unwrap();
        v.put(it, [("token".to_owned(), tok)].into()).unwrap();
    }
    let due_at = |days: i64, secs: i64| {
        let mut d = eng.due_items(t0() + CDuration::days(days) + CDuration::seconds(secs));
        d.sort();
        d
    };
    assert!(due_at(9, 0).is_empty());
    assert_eq!(due_at(10, 0), [per_item]);
    assert_eq!(due_at(17, -1), [per_item]);
    let mut want = vec![per_item, lead];
    want.sort();
    assert_eq!(due_at(17, 0), want);
    assert!(!due_at(29, 0).contains(&default));
    assert!(due_at(30, 0).contains(&default));
    assert!(!due_at(1000, 0).contains(&off));
}

#[tokio::test]
async fn jitter_stays_within_ten_percent() {
    let e = Env::new();
    let eng = e.engine_with(e.device, cfg(0.1));
    let mut ids = vec![];
    for i in 0..20 {
        ids.push(e.admin(
            &format!("j{i}"),
            false,
            0,
            RotationPolicy {
                interval: Some(Duration::from_secs(10 * 86_400)),
                ..RotationPolicy::default()
            },
        ));
    }
    assert!(
        eng.due_items(t0() + CDuration::hours(9 * 24 - 1))
            .is_empty()
    );
    assert_eq!(
        eng.due_items(t0() + CDuration::hours(11 * 24 + 1)).len(),
        20
    );
    let mid = eng.due_items(t0() + CDuration::days(10)).len();
    assert!(mid > 0 && mid < 20, "jitter should spread items, got {mid}");
}

#[tokio::test]
async fn tick_rotates_due_items_and_emits_due() {
    let e = Env::new();
    let id = e.admin("a", false, 1, policy(0));
    let eng = e.engine();
    let mut rx = eng.subscribe();
    assert!(eng.tick().await.unwrap().rotated.is_empty());
    e.clock.advance(CDuration::days(31));
    let t = eng.tick().await.unwrap();
    assert_eq!(t.rotated, [id]);
    assert!(matches!(rx.try_recv().unwrap(), EngineEvent::Due { .. }));
    e.assert_sound(id);
    // Rotated now: next tick has nothing (queued revoke runs, grace 0).
    let t2 = eng.tick().await.unwrap();
    assert!(t2.rotated.is_empty());
    assert_eq!(t2.revokes.len(), 1);
}

#[tokio::test]
async fn locked_vault_skips_and_emits_locked_once() {
    let e = Env::new();
    e.admin("a", false, 1, policy(0));
    let eng = e.engine();
    let mut rx = eng.subscribe();
    e.clock.advance(CDuration::days(31));
    eng.set_locked(true);
    assert!(eng.tick().await.unwrap().skipped_locked);
    assert!(eng.tick().await.unwrap().skipped_locked);
    assert_eq!(rx.try_recv().unwrap(), EngineEvent::Locked);
    assert!(rx.try_recv().is_err());
    assert_eq!(e.fake.calls(), 0);
    eng.set_locked(false);
    assert_eq!(eng.tick().await.unwrap().rotated.len(), 1);
}

#[tokio::test]
async fn rate_limit_backoff_respects_retry_after() {
    let e = Env::new();
    let id = e.admin("a", false, 1, policy(0));
    let eng = e.engine();
    let mut rx = eng.subscribe();
    e.clock.advance(CDuration::days(31));
    e.fake.set_limit(Some(Some(Duration::from_secs(600))));
    let now = e.clock.now();
    assert_eq!(eng.tick().await.unwrap().failed, [id]);
    assert_eq!(
        eng.status(&id),
        ItemStatus::Failed {
            error: "provider rate limited (retry after Some(600s))".into(),
            attempts: 1,
            next_retry: now + CDuration::seconds(600),
        }
    );
    assert_eq!(e.fake.calls(), 1);
    assert_eq!(e.journal_files(), 0);
    e.clock.advance(CDuration::seconds(599));
    assert!(eng.due_items(e.clock.now()).is_empty());
    eng.tick().await.unwrap();
    assert_eq!(e.fake.calls(), 1, "no call before retry_after");
    e.clock.advance(CDuration::seconds(1));
    assert_eq!(eng.due_items(e.clock.now()), [id]);
    // Without retry_after: exponential backoff 60 s, 120 s.
    e.fake.set_limit(Some(None));
    let now = e.clock.now();
    eng.tick().await.unwrap();
    let ItemStatus::Failed {
        next_retry,
        attempts,
        ..
    } = eng.status(&id)
    else {
        panic!()
    };
    assert_eq!((attempts, next_retry), (2, now + CDuration::seconds(120)));
    // Success clears the failure.
    e.fake.set_limit(None);
    e.clock.advance(CDuration::seconds(120));
    assert_eq!(eng.tick().await.unwrap().rotated, [id]);
    assert!(matches!(eng.status(&id), ItemStatus::RevokePending { .. }));
    let mut failed = 0;
    while let Ok(ev) = rx.try_recv() {
        failed += matches!(ev, EngineEvent::Failed { .. }) as u32;
    }
    assert_eq!(failed, 2);
}

#[tokio::test]
async fn run_loop_rotates_and_stops_on_shutdown() {
    let e = Env::new();
    let id = e.admin("a", false, 1, policy(0));
    e.clock.advance(CDuration::days(31));
    let eng = Arc::new(e.engine_with(
        e.device,
        EngineConfig {
            tick: Duration::from_millis(10),
            jitter: 0.0,
            ..EngineConfig::default()
        },
    ));
    let (tx, rx) = tokio::sync::watch::channel(false);
    let h = tokio::spawn({
        let eng = eng.clone();
        async move { eng.run(rx).await }
    });
    for _ in 0..200 {
        if e.vault_value(id) == "tok-1" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(e.vault_value(id), "tok-1");
    tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), h)
        .await
        .unwrap()
        .unwrap();
}

// ---------- MCP ----------

#[tokio::test]
async fn mcp_rate_limit_one_per_item_per_hour() {
    let e = Env::new();
    let a = e.admin("a", false, 1, policy(0));
    let b = e.admin("b", false, 1, policy(0));
    let eng = e.engine();
    assert!(matches!(
        eng.request_rotation(a, RotationSource::Mcp).await.unwrap(),
        RotationRequestOutcome::Rotated(_)
    ));
    let out = eng.request_rotation(a, RotationSource::Mcp).await.unwrap();
    assert_eq!(
        out,
        RotationRequestOutcome::RateLimited {
            retry_at: t0() + CDuration::hours(1)
        }
    );
    // Other item and other sources are not limited.
    assert!(matches!(
        eng.request_rotation(b, RotationSource::Mcp).await.unwrap(),
        RotationRequestOutcome::Rotated(_)
    ));
    assert!(matches!(
        eng.request_rotation(a, RotationSource::Cli).await.unwrap(),
        RotationRequestOutcome::Rotated(_)
    ));
    e.clock.advance(CDuration::minutes(59));
    assert!(matches!(
        eng.request_rotation(a, RotationSource::Mcp).await.unwrap(),
        RotationRequestOutcome::RateLimited { .. }
    ));
    e.clock.advance(CDuration::minutes(1));
    assert!(matches!(
        eng.request_rotation(a, RotationSource::Mcp).await.unwrap(),
        RotationRequestOutcome::Rotated(_)
    ));
}

#[tokio::test]
async fn mcp_atomic_swap_needs_confirmation() {
    let e = Env::new();
    let id = e.admin("a", true, 1, policy(0));
    let eng = e.engine();
    for _ in 0..2 {
        assert_eq!(
            eng.request_rotation(id, RotationSource::Mcp).await.unwrap(),
            RotationRequestOutcome::NeedsConfirmation
        );
    }
    assert_eq!(e.fake.calls(), 0);
    assert_eq!(e.vault_value(id), "adm-a");
    // The desktop app confirms.
    assert!(matches!(
        eng.request_rotation(id, RotationSource::Desktop)
            .await
            .unwrap(),
        RotationRequestOutcome::Rotated(_)
    ));
    e.assert_sound(id);
}

// ---------- review fixes ----------

#[tokio::test]
async fn ambiguous_issue_error_keeps_the_intent_and_recover_verifies() {
    let e = Env::new();
    let id = e.admin("a", true, 1, policy(0));
    let eng = e.engine();
    // A timeout after the provider acted: the old credential is dead, the new one is lost.
    e.fake
        .set_issue_fail(Some(("retryable: request timed out", true)));
    assert!(eng.rotate(id).await.is_err());
    assert_eq!(e.journal_files(), 1, "intent must stay for recover");
    assert!(!e.fake.is_valid(&e.vault_value(id)));
    let mut rx = eng.subscribe();
    drop(eng);
    let eng2 = e.engine();
    let mut rx2 = eng2.subscribe();
    eng2.recover().await.unwrap();
    assert_eq!(e.journal_files(), 1, "the intent is never dropped");
    let mut failed = false;
    while let Ok(ev) = rx2.try_recv() {
        failed |= matches!(ev, EngineEvent::Failed { .. });
    }
    assert!(failed, "recover reports the dead credential");
    assert!(rx.try_recv().is_err());
    // A new rotation does not issue again. It reports that the user must re-enter.
    let calls = e.fake.calls();
    e.fake.set_issue_fail(None);
    let err = eng2.rotate(id).await.unwrap_err().to_string();
    assert!(err.contains("manual re-entry"), "{err}");
    assert_eq!(e.journal_files(), 1);
    assert_eq!(e.fake.calls(), calls + 1, "only the verify call");
    assert!(matches!(eng2.status(&id), ItemStatus::Failed { .. }));
}

#[tokio::test]
async fn first_derived_token_is_created_and_failure_rolls_back() {
    let e = Env::new();
    let admin = e.admin("p", true, 1, policy(0));
    let eng = e.engine();
    let mut item = e.vault_item(e.derived("tmpl", admin, true, 1));
    e.vault.lock().unwrap().delete(&item.id).unwrap();
    item.id = ItemId::new();
    item.name = "fresh".into();
    item.slug = "fresh".into();
    item.provider_token_id = None;
    let id = item.id;
    let r = eng.create_derived(item.clone()).await.unwrap();
    assert!(r.complete);
    assert!(e.fake.is_valid(&e.vault_value(id)));
    assert!(e.vault_item(id).provider_token_id.is_some());
    // A 4xx at the provider removes the new item again.
    let mut bad = item;
    bad.id = ItemId::new();
    bad.name = "bad".into();
    bad.slug = "bad".into();
    bad.provider_token_id = None;
    let bad_id = bad.id;
    e.fake.set_issue_fail(Some(("HTTP 400: bad scope", false)));
    assert!(eng.create_derived(bad).await.is_err());
    assert!(e.vault.lock().unwrap().get(&bad_id).is_none());
}

#[tokio::test]
async fn revoke_404_with_a_dead_credential_stays_queued() {
    let e = Env::new();
    let id = e.admin("a", false, 1, policy(3600));
    let eng = e.engine();
    eng.rotate(id).await.unwrap();
    e.clock.advance(CDuration::hours(2));
    e.fake.set_revoke_404(true);
    // The check of the credential fails: the 404 is not proof that the token is gone.
    let cur = e.vault_value(id);
    e.fake.0.lock().unwrap().valid.remove(&cur);
    let rv = eng.run_pending_revokes().await.unwrap();
    assert!(rv.len() == 1 && !rv[0].done, "{rv:?}");
    assert_eq!(e.journal_files(), 1);
}

#[tokio::test]
async fn validation_error_drops_the_intent() {
    let e = Env::new();
    let id = e.admin("a", false, 1, policy(0));
    let eng = e.engine();
    e.fake.set_issue_fail(Some(("HTTP 400: bad scope", false)));
    assert!(eng.rotate(id).await.is_err());
    assert_eq!(e.journal_files(), 0);
}

#[tokio::test]
async fn recover_continues_after_a_failing_entry() {
    let e = Env::new();
    let a = e.admin("a", true, 1, policy(0));
    let b = e.admin("b", false, 1, policy(0));
    let eng = e.engine();
    eng.inject_fault("intent");
    assert!(eng.rotate(a).await.is_err());
    eng.inject_fault("issued");
    assert!(eng.rotate(b).await.is_err());
    assert_eq!(e.journal_files(), 2);
    // Entry A now fails in recovery: its secret is gone.
    let item = e.vault_item(a);
    e.vault
        .lock()
        .unwrap()
        .put(item, std::collections::BTreeMap::new())
        .unwrap();
    drop(eng);
    let eng2 = e.engine();
    let reps = eng2.recover().await.unwrap();
    assert_eq!(reps.len(), 1, "entry of b is recovered");
    assert_eq!(reps[0].item_id, b);
}

#[tokio::test]
async fn recover_keeps_overlap_intent_for_orphan_cleanup() {
    let e = Env::new();
    let id = e.admin("a", false, 1, policy(0));
    let eng = e.engine();
    eng.inject_fault("intent");
    assert!(eng.rotate(id).await.is_err());
    assert_eq!(e.journal_files(), 1);
    drop(eng);
    let eng2 = e.engine();
    eng2.recover().await.unwrap();
    assert_eq!(e.journal_files(), 1, "overlap intent is kept");
    assert!(matches!(
        eng2.status(&id),
        ItemStatus::Failed { ref error, .. } if error == "rotation interrupted, retry pending"
    ));
    eng2.rotate(id).await.unwrap();
    e.clock.advance(CDuration::hours(2));
    eng2.run_pending_revokes().await.unwrap();
    assert_eq!(e.journal_files(), 0);
}

#[tokio::test]
async fn revoke_of_an_already_revoked_token_is_done() {
    let e = Env::new();
    let id = e.admin("a", false, 1, policy(3600));
    let eng = e.engine();
    eng.rotate(id).await.unwrap();
    e.clock.advance(CDuration::hours(2));
    e.fake.set_revoke_404(true);
    let rv = eng.run_pending_revokes().await.unwrap();
    assert!(rv.len() == 1 && rv[0].done, "{rv:?}");
    assert_eq!(e.journal_files(), 0);
}

#[tokio::test]
async fn same_token_id_still_stores_the_new_value() {
    let e = Env::new();
    let id = e.admin("a", false, 1, policy(0));
    e.fake.0.lock().unwrap().fixed_id = Some("id-a".into());
    let eng = e.engine();
    eng.rotate(id).await.unwrap();
    assert_eq!(e.vault_value(id), "tok-1");
    eng.rotate(id).await.unwrap();
    assert_eq!(e.vault_value(id), "tok-2");
    e.assert_sound(id);
}

#[tokio::test]
async fn empty_token_id_never_queues_a_revoke() {
    let e = Env::new();
    let id = e.admin("a", false, 1, policy(0));
    let mut item = e.vault_item(id);
    item.provider_token_id = Some(String::new());
    let secrets = [("token".to_owned(), SecretValue::new("adm-a"))].into();
    e.vault.lock().unwrap().put(item, secrets).unwrap();
    e.fake.0.lock().unwrap().verify_id = Some(String::new());
    let eng = e.engine();
    let r = eng.rotate(id).await.unwrap();
    assert!(matches!(r.revoke, RevokeState::NotNeeded), "{:?}", r.revoke);
    assert_eq!(e.journal_files(), 0);
}

#[tokio::test]
async fn a_403_is_not_a_dead_credential() {
    let e = Env::new();
    let id = e.admin("a", true, 1, policy(0));
    let eng = e.engine();
    e.fake
        .set_issue_fail(Some(("retryable: request timed out", false)));
    assert!(eng.rotate(id).await.is_err());
    assert_eq!(e.journal_files(), 1);
    e.fake.set_issue_fail(None);
    e.fake.0.lock().unwrap().auth_msg = Some("HTTP 403: forbidden".into());
    let cur = e.vault_value(id);
    e.fake.0.lock().unwrap().valid.remove(&cur);
    let err = eng.rotate(id).await.unwrap_err().to_string();
    assert!(!err.contains("manual re-entry"), "{err}");
    assert_eq!(e.journal_files(), 1);
}

#[tokio::test]
async fn mcp_rate_limit_survives_a_restart() {
    let e = Env::new();
    let a = e.admin("a", false, 1, policy(0));
    assert!(matches!(
        e.engine()
            .request_rotation(a, RotationSource::Mcp)
            .await
            .unwrap(),
        RotationRequestOutcome::Rotated(_)
    ));
    // A new engine has no memory of the request, but the vault has the rotation time.
    e.clock.advance(CDuration::minutes(10));
    assert!(matches!(
        e.engine()
            .request_rotation(a, RotationSource::Mcp)
            .await
            .unwrap(),
        RotationRequestOutcome::RateLimited { .. }
    ));
}

#[tokio::test]
async fn rotation_request_on_a_manual_token_is_refused_and_not_a_failure() {
    let e = Env::new();
    let a = e.admin("m", false, 0, policy(0));
    {
        let mut v = e.vault.lock().unwrap();
        let mut item = v.get(&a).unwrap().clone();
        item.provider = ProviderRef {
            kind: ProviderKind::Manual,
            config: serde_json::json!({}),
        };
        let secret = v.secret(&a, "token").unwrap();
        v.put(item, [("token".to_owned(), secret)].into()).unwrap();
    }
    let eng = e.engine();
    for source in [RotationSource::Mcp, RotationSource::Cli] {
        assert!(matches!(
            eng.request_rotation(a, source).await,
            Err(WardenError::ProviderUnsupported(_))
        ));
    }
    assert!(
        matches!(eng.status(&a), ItemStatus::Idle),
        "{:?}",
        eng.status(&a)
    );
}
