//! Execution of queued revokes of old tokens.

use crate::types::*;
use crate::{Engine, ItemStatus, is_injected, rotate::delta};
use warden_core::{ItemKind, Result, WardenError};

impl Engine {
    /// Execute every queued revoke whose time has come.
    ///
    /// The engine queues a revoke only after every sink holds the new value. A failed revoke
    /// stays queued with a later due time. A revoke never targets the current token of the
    /// item. The credential is the parent admin secret for a derived item and the (new)
    /// own secret for an admin item.
    pub async fn run_pending_revokes(&self) -> Result<Vec<RevokeReport>> {
        let now = self.clock.now();
        let mut out = Vec::new();
        for mut entry in self.journal.load_all()? {
            let Some(task) = entry.revoke.clone() else {
                continue;
            };
            if task.due > now {
                continue;
            }
            let Ok(item) = self.item(&entry.item_id) else {
                self.journal.remove(entry.id)?;
                continue;
            };
            let Some(old) = entry.old_provider_token_id.clone() else {
                self.journal.remove(entry.id)?;
                continue;
            };
            if item.provider_token_id.as_deref() == Some(old.as_str()) {
                self.journal.remove(entry.id)?;
                continue;
            }
            let res = async {
                let provider = (self.providers)(&item.provider)?;
                let cred = match item.kind {
                    ItemKind::Admin => self.secret_of(&item.id)?,
                    ItemKind::Derived { parent } => self.secret_of(&parent)?,
                };
                provider.revoke(&cred, &old).await
            }
            .await;
            // A revoke of a token that is already gone (404) is done.
            let res = match res {
                Err(WardenError::NotFound(_)) => Ok(()),
                Err(WardenError::Provider(m)) if m.starts_with("HTTP 404") => Ok(()),
                other => other,
            };
            match res {
                Ok(()) => {
                    self.checkpoint("revoke_called")?;
                    self.journal.remove(entry.id)?;
                    if matches!(self.status(&item.id), ItemStatus::RevokePending { .. }) {
                        self.set_status(item.id, ItemStatus::Idle);
                    }
                    out.push(RevokeReport {
                        item_id: item.id,
                        provider_token_id: old,
                        done: true,
                        error: None,
                    });
                }
                Err(e) if is_injected(&e) => return Err(e),
                Err(e) => {
                    let attempts = task.attempts + 1;
                    let due = now + delta(self.retry_delay(&e, attempts));
                    entry.revoke = Some(crate::journal::RevokeTask { due, attempts });
                    entry.last_error = Some(e.to_string());
                    self.journal.save(&entry)?;
                    self.set_status(item.id, ItemStatus::RevokePending { due });
                    self.emit(EngineEvent::Failed {
                        item_id: item.id,
                        name: item.name.clone(),
                        error: format!("revoke of old token failed: {e}"),
                        next_retry: Some(due),
                    });
                    out.push(RevokeReport {
                        item_id: item.id,
                        provider_token_id: old,
                        done: false,
                        error: Some(match e {
                            WardenError::Config(m) => m,
                            other => other.to_string(),
                        }),
                    });
                }
            }
        }
        Ok(out)
    }
}
