//! Desktop notifications of the daemon. Each note (kind and token) shows at most once per
//! week. The last time of each note lives in a file, so a daemon restart does not repeat it.

use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use warden_engine::EngineEvent;

/// Minimum gap between two notes with the same key.
pub const NOTE_GAP_DAYS: i64 = 7;

/// Key of the weekly coffee note.
pub const KEY_COFFEE: &str = "coffee";

/// Shows desktop notifications and drops a note that showed in the last week.
#[derive(Debug)]
pub struct Notifier {
    enabled: bool,
    file: PathBuf,
    seen: Mutex<HashMap<String, DateTime<Utc>>>,
}

impl Notifier {
    /// Load the note times from `file`. A missing or bad file starts empty.
    /// `enabled` false only logs the title (tests, `WARDEN_NO_NOTIFY`).
    pub fn new(enabled: bool, file: PathBuf) -> Self {
        let seen = std::fs::read(&file)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        Self {
            enabled,
            file,
            seen: Mutex::new(seen),
        }
    }

    /// Return true and record `now` when the note `key` did not show in the last week.
    pub fn allow(&self, key: &str, now: DateTime<Utc>) -> bool {
        let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        if !allowed(&seen, key, now) {
            return false;
        }
        seen.insert(key.to_owned(), now);
        seen.retain(|_, t| now - *t < Duration::days(NOTE_GAP_DAYS));
        if let Err(e) = save(&self.file, &seen) {
            tracing::warn!("cannot save the notification times: {e}");
        }
        true
    }

    /// Show the note when [`Notifier::allow`] permits it.
    pub async fn show(&self, key: &str, title: String, body: String) {
        if !self.allow(key, Utc::now()) {
            tracing::debug!("notification held back (shown this week): {title}");
            return;
        }
        if !self.enabled {
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
}

fn allowed(seen: &HashMap<String, DateTime<Utc>>, key: &str, now: DateTime<Utc>) -> bool {
    seen.get(key)
        .is_none_or(|last| now - *last >= Duration::days(NOTE_GAP_DAYS))
}

fn save(file: &std::path::Path, seen: &HashMap<String, DateTime<Utc>>) -> std::io::Result<()> {
    if let Some(dir) = file.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = file.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(seen)?)?;
    std::fs::rename(tmp, file)
}

/// Key of the note for an engine event: the kind and the token.
pub fn event_key(ev: &EngineEvent) -> String {
    match ev {
        EngineEvent::Rotated {
            item_id, complete, ..
        } => format!("rotated:{complete}:{item_id}"),
        EngineEvent::Failed { item_id, .. } => format!("failed:{item_id}"),
        EngineEvent::Due { item_id, .. } => format!("due:{item_id}"),
        EngineEvent::ExpiringSoon { item_id, .. } => format!("expiring:{item_id}"),
        other => format!("{other:?}")
            .split([' ', '{', '('])
            .next()
            .unwrap_or("other")
            .to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("warden-notes-{name}-{}.json", std::process::id()))
    }

    #[test]
    fn same_note_shows_once_per_week() {
        let f = tmp("week");
        let n = Notifier::new(false, f.clone());
        let t0 = Utc::now();
        assert!(n.allow("failed:a", t0));
        assert!(!n.allow("failed:a", t0 + Duration::hours(1)));
        assert!(!n.allow("failed:a", t0 + Duration::days(6)));
        assert!(n.allow("failed:b", t0 + Duration::hours(1)));
        assert!(n.allow("failed:a", t0 + Duration::days(7)));
        let _ = std::fs::remove_file(f);
    }

    #[test]
    fn a_restart_keeps_the_note_times() {
        let f = tmp("restart");
        let t0 = Utc::now();
        assert!(Notifier::new(false, f.clone()).allow("due:x", t0));
        let again = Notifier::new(false, f.clone());
        assert!(!again.allow("due:x", t0 + Duration::hours(2)));
        let _ = std::fs::remove_file(f);
    }

    #[test]
    fn bad_file_starts_empty() {
        let f = tmp("bad");
        std::fs::write(&f, b"not json").unwrap();
        assert!(Notifier::new(false, f.clone()).allow("x", Utc::now()));
        let _ = std::fs::remove_file(f);
    }
}
