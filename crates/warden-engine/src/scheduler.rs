//! Scheduler: which items are due, and the tick loop.

use crate::types::*;
use crate::{Engine, ItemStatus, lock};
use chrono::{DateTime, Utc};
use std::collections::HashSet;
use std::time::Duration;
use tokio::sync::watch;
use warden_core::{Item, ItemId, ProviderKind, Result, Settings, next_rotation};

fn splitmix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

impl Engine {
    /// Next rotation time of an item. The interval part carries a stable jitter
    /// (plus or minus `config.jitter`, derived from the item id and the last rotation).
    /// The lead time before the end date has no jitter.
    pub(crate) fn scheduled_at(
        &self,
        item: &Item,
        settings: &Settings,
        now: DateTime<Utc>,
    ) -> Option<DateTime<Utc>> {
        let interval = item.policy.interval.unwrap_or(settings.default_interval);
        let base = item.rotated_at.unwrap_or(item.created_at);
        let r = splitmix(
            (item.id.as_uuid().as_u128() as u64) ^ (base.timestamp() as u64).rotate_left(17),
        );
        let unit = (r >> 11) as f64 / (1u64 << 53) as f64; // [0, 1)
        let j = self.config.jitter.clamp(0.0, 0.5);
        let factor = 1.0 + (unit * 2.0 - 1.0) * j;
        let jittered =
            Duration::try_from_secs_f64(interval.as_secs_f64() * factor).unwrap_or(interval);
        let mut it = item.clone();
        it.policy.interval = Some(jittered);
        next_rotation(&it, settings, now)
    }

    /// Items that are due at `now` on this device.
    ///
    /// Uses `warden_core::next_rotation` (per-item interval or the global default, lead time
    /// before the end date) with jitter on the interval. It skips items of other rotator
    /// devices, items with a rotation in flight, and items in backoff.
    pub fn due_items(&self, now: DateTime<Utc>) -> Vec<ItemId> {
        let settings = *lock(&self.settings);
        let inflight: HashSet<ItemId> = self
            .journal
            .load_all()
            .unwrap_or_default()
            .into_iter()
            .filter(|e| e.revoke.is_none())
            .map(|e| e.item_id)
            .collect();
        let items: Vec<Item> = lock(&self.vault).items().into_iter().cloned().collect();
        let st = lock(&self.state);
        items
            .into_iter()
            .filter(|i| i.rotator_device == self.device_id)
            .filter(|i| !st.busy.contains(&i.id) && !inflight.contains(&i.id))
            .filter(|i| {
                !matches!(st.statuses.get(&i.id),
                    Some(ItemStatus::Failed { next_retry, .. }) if *next_retry > now)
            })
            .filter(|i| {
                self.scheduled_at(i, &settings, now)
                    .is_some_and(|t| t <= now)
            })
            .map(|i| i.id)
            .collect()
    }

    /// One scheduler pass: queued revokes, retries of in-flight rotations, due items.
    ///
    /// Skips everything and emits `Locked` (once per lock) when the vault is locked.
    /// Rotates due items one at a time.
    pub async fn tick(&self) -> Result<TickReport> {
        let mut rep = TickReport::default();
        {
            let mut s = lock(&self.state);
            if s.locked {
                if !s.locked_notified {
                    s.locked_notified = true;
                    drop(s);
                    self.emit(EngineEvent::Locked);
                }
                rep.skipped_locked = true;
                return Ok(rep);
            }
        }
        let now = self.now();
        rep.revokes = self.run_pending_revokes().await?;
        // Retry in-flight rotations whose backoff ended.
        for stale in self.journal.load_all()? {
            if stale.revoke.is_some() || stale.issued.is_none() {
                continue;
            }
            if stale.next_attempt.is_some_and(|t| t > now) {
                continue;
            }
            let Ok(_busy) = self.busy(stale.item_id) else {
                continue;
            };
            // The entry can change or go away while this loop waits: reload under the guard.
            let Some(mut entry) = self.journal.load(stale.id)? else {
                continue;
            };
            if entry.revoke.is_some() || entry.issued.is_none() {
                continue;
            }
            match self.drive_guarded(&mut entry).await {
                Ok(_) => rep.rotated.push(entry.item_id),
                Err(_) => rep.failed.push(entry.item_id),
            }
        }
        self.notify_expiring(now);
        for id in self.due_items(now) {
            let Ok(item) = self.item(&id) else { continue };
            let first = lock(&self.state).due_notified.insert(id);
            if first {
                self.emit(EngineEvent::Due {
                    item_id: id,
                    name: item.name.clone(),
                });
            }
            if item.provider.kind == ProviderKind::Manual {
                continue;
            }
            match self.rotate(id).await {
                Ok(_) => rep.rotated.push(id),
                Err(e) => {
                    tracing::warn!("scheduled rotation of {id} failed: {e}");
                    rep.failed.push(id);
                }
            }
        }
        Ok(rep)
    }

    fn notify_expiring(&self, now: DateTime<Utc>) {
        let items: Vec<Item> = lock(&self.vault).items().into_iter().cloned().collect();
        for i in items {
            let Some(exp) = i.expires_at else { continue };
            if i.rotator_device != self.device_id || exp <= now {
                continue;
            }
            let handled = i.policy.auto_rotate && i.provider.kind != ProviderKind::Manual;
            if handled || now < exp - crate::rotate::delta(i.policy.lead_time) {
                continue;
            }
            if lock(&self.state).expiring_notified.insert(i.id) {
                self.emit(EngineEvent::ExpiringSoon {
                    item_id: i.id,
                    name: i.name,
                    expires_at: exp,
                });
            }
        }
    }

    /// Run the scheduler until `shutdown` turns `true` (or its sender drops).
    /// A pass runs every `config.tick` (60 s). Call [`Engine::recover`] before.
    pub async fn run(&self, mut shutdown: watch::Receiver<bool>) {
        loop {
            if *shutdown.borrow() {
                return;
            }
            if let Err(e) = self.tick().await {
                tracing::warn!("scheduler pass failed: {e}");
            }
            tokio::select! {
                () = tokio::time::sleep(self.config.tick) => {}
                r = shutdown.changed() => {
                    if r.is_err() || *shutdown.borrow() {
                        return;
                    }
                }
            }
        }
    }
}
