//! The rotation state machine, recovery and the MCP rate limit.

use crate::journal::{self, Issued, JournalEntry, RevokeTask};
use crate::types::*;
use crate::{Engine, TOKEN_SECRET, is_injected, lock};
use chrono::{DateTime, TimeDelta, Utc};
use std::collections::BTreeMap;
use std::time::Duration;
use uuid::Uuid;
use warden_core::{
    CreateRequest, Item, ItemId, ItemKind, Provider, ProviderKind, Result, RotateRequest,
    RotationClass, SecretValue, WardenError, provider_token_name,
};

const DEAD_CREDENTIAL: &str =
    "needs manual re-entry: the credential is no longer valid after an interrupted rotation";

pub(crate) struct BusyGuard<'a> {
    engine: &'a Engine,
    id: ItemId,
}

impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        lock(&self.engine.state).busy.remove(&self.id);
    }
}

/// `true` when the error proves that the provider did not issue a token.
fn proves_not_issued(e: &WardenError) -> bool {
    match e {
        WardenError::ProviderAuth(_)
        | WardenError::ProviderRateLimited { .. }
        | WardenError::ProviderUnsupported(_)
        | WardenError::Config(_)
        | WardenError::NotFound(_)
        | WardenError::Locked
        | WardenError::Vault(_) => true,
        // A 4xx validation error. Timeouts and 5xx ("retryable: ...") are ambiguous.
        WardenError::Provider(m) => m.starts_with("HTTP 4"),
        _ => false,
    }
}

/// `true` when a `ProviderAuth` message proves a dead credential. Only HTTP 401 does.
/// A 403 can come from a missing scope or a policy, so it stays a retryable failure.
/// AWS answers a dead access key with 403 and the code `InvalidClientTokenId`.
/// Cloudflare verify answers 200 with a status other than `active` for a disabled token.
fn proves_dead(msg: &str) -> bool {
    msg.starts_with("HTTP 401")
        || msg.contains("InvalidClientTokenId")
        || msg.starts_with("token status is")
}

/// A seal failure after the provider call. It must never prove "not issued".
fn seal_failed(e: WardenError) -> WardenError {
    WardenError::Provider(format!("retryable: could not seal the new credential: {e}"))
}

pub(crate) fn delta(d: Duration) -> TimeDelta {
    TimeDelta::from_std(d).unwrap_or(TimeDelta::MAX)
}

impl Engine {
    pub(crate) fn busy(&self, id: ItemId) -> Result<BusyGuard<'_>> {
        let mut s = lock(&self.state);
        if !s.busy.insert(id) {
            return Err(WardenError::Config("rotation already running".into()));
        }
        Ok(BusyGuard { engine: self, id })
    }

    /// Delay before the next retry after a failure.
    pub(crate) fn retry_delay(&self, e: &WardenError, attempts: u32) -> Duration {
        if let WardenError::ProviderRateLimited {
            retry_after: Some(d),
        } = e
        {
            return *d;
        }
        let exp = self
            .config
            .backoff_base
            .saturating_mul(1u32 << attempts.saturating_sub(1).min(20));
        exp.min(self.config.backoff_max)
    }

    pub(crate) fn require_rotator(&self, item: &Item) -> Result<()> {
        if item.rotator_device != self.device_id {
            return Err(WardenError::Config("not the rotator device".into()));
        }
        Ok(())
    }

    /// Rotate one item now.
    ///
    /// Refuses when this device is not the rotator of the item. Resumes an in-flight
    /// rotation of the item instead of starting a new one. Provider errors return `Err`.
    /// Sink failures return `Ok` with `complete == false` and set the status to `Failed`.
    pub async fn rotate(&self, item_id: ItemId) -> Result<RotationReport> {
        let item = self.item(&item_id)?;
        self.require_rotator(&item)?;
        let _busy = self.busy(item_id)?;
        let resume = self
            .journal
            .load_all()?
            .into_iter()
            .find(|e| e.item_id == item_id && e.revoke.is_none());
        let mut entry = match resume {
            Some(e) => {
                if e.issued.is_none() {
                    self.check_before_reissue(&item, &e).await?;
                }
                e
            }
            None => {
                let provider = (self.providers)(&item.provider)?;
                let now = self.clock.now();
                let mut old = item.provider_token_id.clone().filter(|s| !s.is_empty());
                // An admin key that was added by hand has no stored id yet. Ask the provider,
                // so the rotation can revoke the old key.
                if old.is_none()
                    && item.kind == ItemKind::Admin
                    && provider.class() == RotationClass::Overlap
                    && let Ok(cred) = self.secret_of(&item.id)
                    && let Ok(info) = provider.verify(&cred).await
                {
                    old = Some(info.provider_token_id).filter(|s| !s.is_empty());
                }
                let e = JournalEntry {
                    id: Uuid::now_v7(),
                    item_id,
                    class: provider.class(),
                    started_at: now,
                    old_provider_token_id: old,
                    token_name: provider_token_name(&item.slug, now.date_naive()),
                    issued: None,
                    stored: false,
                    sinks_done: false,
                    revoke: None,
                    attempts: 0,
                    next_attempt: None,
                    last_error: None,
                };
                self.journal.save(&e)?;
                self.checkpoint("intent")?;
                e
            }
        };
        self.drive_guarded(&mut entry).await
    }

    /// An earlier attempt may have acted at the provider without a reply. Check the provider
    /// state before the engine issues again. Never drops the intent.
    async fn check_before_reissue(&self, item: &Item, entry: &JournalEntry) -> Result<()> {
        if entry.class != RotationClass::AtomicSwap || item.kind != ItemKind::Admin {
            return Ok(());
        }
        let provider = (self.providers)(&item.provider)?;
        let cred = self.secret_of(&item.id)?;
        match provider.verify(&cred).await {
            Ok(_) => Ok(()),
            Err(WardenError::ProviderAuth(m)) if proves_dead(&m) => {
                self.mark_dead(item, entry.attempts + 1, DEAD_CREDENTIAL);
                Err(WardenError::Config(DEAD_CREDENTIAL.into()))
            }
            Err(e) => Err(e),
        }
    }

    /// Set the status `Failed` and tell the user that a new credential is needed.
    pub(crate) fn mark_dead(&self, item: &Item, attempts: u32, msg: &str) {
        let next_retry = self.clock.now() + delta(self.config.backoff_max);
        self.set_status(
            item.id,
            ItemStatus::Failed {
                error: msg.into(),
                attempts,
                next_retry,
            },
        );
        self.emit(EngineEvent::Failed {
            item_id: item.id,
            name: item.name.clone(),
            error: msg.into(),
            next_retry: None,
        });
    }

    /// Create the first token of a derived item at the provider, store it and write the sinks.
    ///
    /// The item must be `Derived` and this device must be its rotator. The item enters the
    /// vault first (empty value). When the provider proves that it issued nothing, the item is
    /// removed again. A sink failure keeps the item and returns a report with `complete == false`.
    pub async fn create_derived(&self, item: Item) -> Result<RotationReport> {
        if !matches!(item.kind, ItemKind::Derived { .. }) {
            return Err(WardenError::Config("item is not derived".into()));
        }
        let id = item.id;
        self.with_vault(|v| {
            v.put(
                item,
                [(TOKEN_SECRET.to_owned(), SecretValue::new(""))]
                    .into_iter()
                    .collect(),
            )
        })?;
        match self.rotate(id).await {
            Ok(r) => Ok(r),
            Err(e) => {
                if proves_not_issued(&e) {
                    let _ = self.with_vault(|v| v.delete(&id));
                }
                Err(e)
            }
        }
    }

    /// Provider config plus hints for the orphan cleanup (`Overlap` only).
    fn hinted_config(&self, item: &Item, entry: &JournalEntry) -> serde_json::Value {
        let mut c = item.provider.config.clone();
        if entry.class == RotationClass::Overlap
            && let Some(o) = c.as_object_mut()
        {
            o.insert(
                "_warden_intent_at".into(),
                entry.started_at.to_rfc3339().into(),
            );
            if let Some(id) = &item.provider_token_id {
                o.insert("_warden_current_id".into(), id.clone().into());
            }
        }
        c
    }

    /// Run `drive` and record a failure in the status, the journal and the event channel.
    pub(crate) async fn drive_guarded(&self, entry: &mut JournalEntry) -> Result<RotationReport> {
        let prev = match self.status(&entry.item_id) {
            ItemStatus::Failed { attempts, .. } => attempts,
            _ => 0,
        }
        .max(entry.attempts);
        self.set_status(entry.item_id, ItemStatus::Rotating);
        match self.drive(entry).await {
            Ok(r) => Ok(r),
            Err(e) if is_injected(&e) => Err(e),
            Err(e) => {
                self.note_failure(entry, &e, prev + 1);
                Err(e)
            }
        }
    }

    fn note_failure(&self, entry: &mut JournalEntry, e: &WardenError, attempts: u32) {
        let next = self.clock.now() + delta(self.retry_delay(e, attempts));
        let name = self
            .item(&entry.item_id)
            .map(|i| i.name)
            .unwrap_or_default();
        self.set_status(
            entry.item_id,
            ItemStatus::Failed {
                error: e.to_string(),
                attempts,
                next_retry: next,
            },
        );
        if entry.issued.is_some() {
            entry.attempts = attempts;
            entry.next_attempt = Some(next);
            entry.last_error = Some(e.to_string());
            if let Err(je) = self.journal.save(entry) {
                tracing::error!("journal save failed: {je}");
            }
        }
        self.emit(EngineEvent::Failed {
            item_id: entry.item_id,
            name,
            error: e.to_string(),
            next_retry: Some(next),
        });
    }

    async fn drive(&self, entry: &mut JournalEntry) -> Result<RotationReport> {
        let item = self.item(&entry.item_id)?;
        let provider = (self.providers)(&item.provider)?;
        if entry.issued.is_none() {
            match self.issue(&item, provider.as_ref(), entry).await {
                Ok(issued) => entry.issued = Some(issued),
                Err(e) => {
                    // Drop the intent only when the error proves "not issued". A timeout or
                    // a 5xx can follow an action at the provider: keep the intent and let
                    // `recover` verify.
                    if proves_not_issued(&e) {
                        self.journal.remove(entry.id)?;
                    }
                    return Err(e);
                }
            }
            self.journal.save(entry)?;
            self.checkpoint("issued")?;
        }
        let issued = entry.issued.clone().expect("issued is set");
        let value = SecretValue::new(journal::open(
            &self.vault_key(),
            &entry.id.to_string(),
            &issued.sealed,
        )?);
        let mut outcomes: Vec<SinkOutcome> = Vec::new();
        let phases: [bool; 2] = if entry.class == RotationClass::Overlap {
            [false, true] // sinks first, then store
        } else {
            [true, false] // store first, then sinks
        };
        for store_phase in phases {
            if store_phase {
                if !entry.stored {
                    self.store(&item, &issued, &value)?;
                    entry.stored = true;
                    self.journal.save(entry)?;
                    self.checkpoint("stored")?;
                }
            } else if !entry.sinks_done {
                outcomes = self.write_sinks(&item, &value).await?;
                if outcomes.iter().any(|o| !o.ok) {
                    return Ok(self.fail_forward(entry, &item, &issued, outcomes));
                }
                entry.sinks_done = true;
                self.journal.save(entry)?;
                self.checkpoint("sinks")?;
            }
        }
        if outcomes.is_empty() {
            outcomes = item
                .sinks
                .iter()
                .map(|s| SinkOutcome {
                    sink: format!("{s:?}"),
                    ok: true,
                    error: None,
                })
                .collect();
        }
        // Revoke of the old token. Only now: every sink holds the new value.
        let caps = provider.capabilities();
        let derived = matches!(item.kind, ItemKind::Derived { .. });
        let old = entry.old_provider_token_id.clone();
        let needs_revoke = caps.revoke
            && old.is_some()
            && old.as_deref() != Some(issued.provider_token_id.as_str())
            && (entry.class == RotationClass::Overlap || derived);
        let revoke = if needs_revoke {
            let grace = if entry.class == RotationClass::Overlap {
                item.policy.grace
            } else {
                Duration::ZERO
            };
            let due = self.clock.now() + delta(grace);
            entry.revoke = Some(RevokeTask { due, attempts: 0 });
            entry.attempts = 0;
            entry.next_attempt = None;
            self.journal.save(entry)?;
            self.checkpoint("revoke_queued")?;
            self.set_status(item.id, ItemStatus::RevokePending { due });
            self.emit(EngineEvent::RevokePending {
                item_id: item.id,
                name: item.name.clone(),
                due,
            });
            RevokeState::Pending { due }
        } else {
            self.journal.remove(entry.id)?;
            self.set_status(item.id, ItemStatus::Idle);
            RevokeState::NotNeeded
        };
        {
            let mut s = lock(&self.state);
            s.due_notified.remove(&item.id);
            s.expiring_notified.remove(&item.id);
        }
        self.emit(EngineEvent::Rotated {
            item_id: item.id,
            name: item.name.clone(),
            complete: true,
        });
        Ok(RotationReport {
            item_id: item.id,
            class: entry.class,
            new_provider_token_id: issued.provider_token_id,
            expires_at: issued.expires_at,
            sinks: outcomes,
            revoke,
            complete: true,
        })
    }

    /// Sinks failed: keep the journal, set the retry time, report per sink.
    fn fail_forward(
        &self,
        entry: &mut JournalEntry,
        item: &Item,
        issued: &Issued,
        outcomes: Vec<SinkOutcome>,
    ) -> RotationReport {
        let msg = outcomes
            .iter()
            .filter(|o| !o.ok)
            .map(|o| format!("{}: {}", o.sink, o.error.as_deref().unwrap_or("failed")))
            .collect::<Vec<_>>()
            .join("; ");
        let err = WardenError::Sink(msg);
        self.note_failure(entry, &err, entry.attempts + 1);
        RotationReport {
            item_id: item.id,
            class: entry.class,
            new_provider_token_id: issued.provider_token_id.clone(),
            expires_at: issued.expires_at,
            sinks: outcomes,
            revoke: RevokeState::NotNeeded,
            complete: false,
        }
    }

    /// Call the provider and seal the new value.
    async fn issue(
        &self,
        item: &Item,
        provider: &dyn Provider,
        entry: &JournalEntry,
    ) -> Result<Issued> {
        let caps = provider.capabilities();
        let token = match item.kind {
            ItemKind::Admin => {
                if !caps.self_rotate {
                    return Err(WardenError::ProviderUnsupported("self rotation".into()));
                }
                let cred = self.secret_of(&item.id)?;
                let req = RotateRequest {
                    item_id: item.id,
                    token_name: entry.token_name.clone(),
                    provider_token_id: item.provider_token_id.clone(),
                    config: self.hinted_config(item, entry),
                    expires_at: None,
                };
                provider.rotate_self(&cred, &req).await?
            }
            ItemKind::Derived { parent } => {
                if !caps.create_derived {
                    return Err(WardenError::ProviderUnsupported("create derived".into()));
                }
                let p = self.item(&parent)?;
                if p.kind != ItemKind::Admin {
                    return Err(WardenError::Config("parent is not an admin item".into()));
                }
                let admin = self.secret_of(&parent)?;
                let scopes = item
                    .provider
                    .config
                    .get("scopes")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|s| s.as_str().map(str::to_owned))
                            .collect()
                    })
                    .unwrap_or_default();
                let req = CreateRequest {
                    item_id: item.id,
                    token_name: entry.token_name.clone(),
                    config: self.hinted_config(item, entry),
                    scopes,
                    expires_at: None,
                };
                provider.create_derived(&admin, &req).await?
            }
        };
        Ok(Issued {
            sealed: journal::seal(
                &self.vault_key(),
                &entry.id.to_string(),
                token.value.expose(),
            )
            .map_err(seal_failed)?,
            provider_token_id: token.provider_token_id,
            expires_at: token.expires_at,
        })
    }

    /// Put the new value and metadata into the vault (idempotent).
    fn store(&self, item: &Item, issued: &Issued, value: &SecretValue) -> Result<()> {
        let now = self.clock.now();
        self.with_vault(|v| {
            let mut cur = v
                .get(&item.id)
                .cloned()
                .ok_or_else(|| WardenError::NotFound(format!("item {}", item.id)))?;
            // Skip only when the vault already holds this id and this value. A provider can
            // keep the id and change the value (Cloudflare roll).
            if cur.provider_token_id.as_deref() == Some(issued.provider_token_id.as_str())
                && v.secret(&item.id, TOKEN_SECRET)
                    .is_ok_and(|s| s.expose() == value.expose())
            {
                return Ok(());
            }
            let mut secrets: BTreeMap<String, SecretValue> = BTreeMap::new();
            for n in v.secret_names(&item.id) {
                if n != TOKEN_SECRET {
                    secrets.insert(n.clone(), v.secret(&item.id, &n)?);
                }
            }
            secrets.insert(TOKEN_SECRET.to_owned(), value.clone());
            cur.provider_token_id = Some(issued.provider_token_id.clone());
            cur.expires_at = issued.expires_at;
            cur.rotated_at = Some(now);
            v.put(cur, secrets)
        })
    }

    /// Write every sink and read it back. One outcome per sink.
    async fn write_sinks(&self, item: &Item, value: &SecretValue) -> Result<Vec<SinkOutcome>> {
        let mut out = Vec::new();
        for (i, spec) in item.sinks.iter().enumerate() {
            let o = match (self.sinks)(spec) {
                Err(e) => SinkOutcome {
                    sink: format!("{spec:?}"),
                    ok: false,
                    error: Some(e.to_string()),
                },
                Ok(sink) => {
                    let desc = sink.describe();
                    let res = match sink.write(value).await {
                        Err(e) => Err(e.to_string()),
                        Ok(()) => match sink.read_back_matches(value).await {
                            Ok(true) => Ok(()),
                            Ok(false) => Err("read back does not match".to_owned()),
                            Err(e) => Err(e.to_string()),
                        },
                    };
                    SinkOutcome {
                        sink: desc,
                        ok: res.is_ok(),
                        error: res.err(),
                    }
                }
            };
            out.push(o);
            self.checkpoint(&format!("sink{i}"))?;
        }
        Ok(out)
    }

    /// Complete or resume every journal entry. Call it once on startup.
    ///
    /// - New token issued but not in the vault: store it.
    /// - Sinks not written: write them (forward, never restore).
    /// - Intent only (`Overlap`): keep it and mark the item `Failed`. The provider may hold
    ///   an orphan key. The next rotation resumes the intent and cleans it up.
    /// - Intent only (`AtomicSwap`): verify the vault value. Valid: drop the intent.
    ///   Invalid: emit `Failed` (the provider swapped the token before the journal write).
    /// - Queued revoke: left for [`Engine::run_pending_revokes`].
    pub async fn recover(&self) -> Result<Vec<RotationReport>> {
        let mut reports = Vec::new();
        for stale in self.journal.load_all()? {
            let mut entry = stale;
            let Ok(item) = self.item(&entry.item_id) else {
                if let Err(e) = self.journal.remove(entry.id) {
                    tracing::warn!("journal remove failed: {e}");
                }
                continue;
            };
            if let Some(r) = &entry.revoke {
                self.set_status(item.id, ItemStatus::RevokePending { due: r.due });
                continue;
            }
            if entry.issued.is_none() {
                if let Err(e) = self.recover_intent(&entry, &item).await {
                    tracing::warn!("recovery of intent of {} failed: {e}", item.id);
                }
                continue;
            }
            let Ok(_busy) = self.busy(item.id) else {
                continue;
            };
            // Reload under the guard: skip an entry that is gone or that changed.
            match self.journal.load(entry.id) {
                Ok(Some(fresh)) if fresh.revoke.is_none() && fresh.issued.is_some() => {
                    entry = fresh;
                }
                Ok(_) => continue,
                Err(e) => {
                    tracing::warn!("journal reload of {} failed: {e}", item.id);
                    continue;
                }
            }
            match self.drive_guarded(&mut entry).await {
                Ok(r) => reports.push(r),
                Err(e) => tracing::warn!("recovery of {} failed: {e}", item.id),
            }
        }
        Ok(reports)
    }

    async fn recover_intent(&self, entry: &JournalEntry, item: &Item) -> Result<()> {
        if entry.class == RotationClass::AtomicSwap && item.kind == ItemKind::Admin {
            let provider = (self.providers)(&item.provider)?;
            let cred = self.secret_of(&item.id)?;
            if let Err(e) = provider.verify(&cred).await {
                if matches!(&e, WardenError::ProviderAuth(m) if proves_dead(m)) {
                    // Keep the intent. The user must enter a new credential.
                    self.mark_dead(item, entry.attempts + 1, DEAD_CREDENTIAL);
                }
                return Ok(()); // keep the intent, try again on the next recover
            }
        }
        if entry.class == RotationClass::Overlap {
            // The reply of a create call may be lost. Keep the intent (with its start time),
            // so the provider can find and delete an orphan key on the next rotation.
            self.set_status(
                item.id,
                ItemStatus::Failed {
                    error: "rotation interrupted, retry pending".into(),
                    attempts: entry.attempts + 1,
                    next_retry: self.clock.now(),
                },
            );
            return Ok(());
        }
        self.journal.remove(entry.id)
    }

    /// Request a rotation for a source.
    ///
    /// - `Mcp`: at most one rotation per item per `mcp_min_interval` (1 h). `AtomicSwap`
    ///   items return `NeedsConfirmation` and do not rotate.
    /// - Other sources rotate at once.
    pub async fn request_rotation(
        &self,
        item_id: ItemId,
        source: RotationSource,
    ) -> Result<RotationRequestOutcome> {
        let item = self.item(&item_id)?;
        // A manual token has nothing to rotate. Refuse before the attempt, so the request
        // does not mark the item as failed.
        if item.provider.kind == ProviderKind::Manual {
            return Err(WardenError::ProviderUnsupported(
                "a manual token cannot rotate. Make a new one at the provider and update the token"
                    .into(),
            ));
        }
        if source == RotationSource::Mcp {
            self.require_rotator(&item)?;
            if (self.providers)(&item.provider)?.class() == RotationClass::AtomicSwap {
                return Ok(RotationRequestOutcome::NeedsConfirmation);
            }
            let now = self.clock.now();
            // Check and record under one lock, so two parallel requests cannot both pass.
            // The last rotation in the vault also counts, so a daemon restart keeps the limit.
            let mut st = lock(&self.state);
            let last = st.mcp_last.get(&item_id).copied().max(item.rotated_at);
            if let Some(l) = last {
                let retry_at = l + delta(self.config.mcp_min_interval);
                if now < retry_at {
                    return Ok(RotationRequestOutcome::RateLimited { retry_at });
                }
            }
            st.mcp_last.insert(item_id, now);
        }
        self.rotate(item_id)
            .await
            .map(RotationRequestOutcome::Rotated)
    }

    pub(crate) fn now(&self) -> DateTime<Utc> {
        self.clock.now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_failure_never_proves_not_issued() {
        let e = seal_failed(WardenError::Vault("journal seal failed".into()));
        assert!(!proves_not_issued(&e));
    }

    #[test]
    fn only_401_proves_a_dead_credential() {
        assert!(proves_dead("HTTP 401: nope"));
        assert!(proves_dead("token status is disabled"));
        assert!(!proves_dead("HTTP 403: nope"));
    }
}
