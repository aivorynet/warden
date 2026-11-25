//! The coffee honor system and the weekly reminder note.
//!
//! Warden follows the Hopover model. It cannot see a payment, so it trusts the user. The user
//! confirms a payment, and [`mark_paid`] stores the year. There is no server and no network call.
//! The reminder never blocks any other work.

use chrono::{DateTime, Datelike, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use warden_core::Clock;

mod pledge;
pub use pledge::*;

/// Link where the user pays for a coffee. The shared Aivory donation link, no query string.
pub const COFFEE_URL: &str = "https://buy.stripe.com/5kQbJ3csm21Xfz64DhdjO00";
/// Title of the reminder note.
pub const NOTE_TITLE: &str = "Aivory Warden is free. A coffee keeps it that way.";
/// Body of the reminder note.
pub const NOTE_BODY: &str = "If Warden saves you time, buy the developer a coffee: https://buy.stripe.com/5kQbJ3csm21Xfz64DhdjO00 . Use Settings > Buy a coffee or run `awd coffee --pay`. If you paid, run `awd coffee --paid` to stop this note for the year. Turn the note off in Settings.";
/// Minimum time between two notes.
pub const NOTE_INTERVAL_DAYS: i64 = 7;

/// Error of coffee state storage.
#[derive(Debug, thiserror::Error)]
pub enum CoffeeError {
    /// The settings file has no valid shape.
    #[error("malformed settings file")]
    Malformed,
    /// A file failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// A JSON failure.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Coffee state in the local settings file. It is not synced.
///
/// Unknown fields in an old settings file are ignored when the file loads.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CoffeeState {
    /// Year that the user confirmed as paid, if any.
    pub paid_year: Option<i32>,
    /// Time when the user confirmed the payment.
    pub paid_at: Option<DateTime<Utc>>,
    /// Time of the last reminder note.
    pub last_note_at: Option<DateTime<Utc>>,
    /// Time when the user signed the coffee pledge at first run.
    pub pledge_signed_at: Option<DateTime<Utc>>,
    /// User name that signed the pledge.
    pub pledge_signed_by: Option<String>,
    /// The note after the first successful rotation was shown.
    pub first_rotation_noted: bool,
    /// Successful rotations since the last note.
    pub rotations_since_note: u32,
}

impl CoffeeState {
    /// Return true when a confirmed payment covers the current year.
    pub fn is_paid(&self, clock: &dyn Clock) -> bool {
        self.paid_year == Some(clock.now().year())
    }
}

/// Return true when the reminder note is due now.
///
/// The note is due when the reminder is on, no confirmed payment covers the current year, and
/// the last note is at least 7 days old (or there was none).
pub fn should_show_note(state: &CoffeeState, reminder_enabled: bool, clock: &dyn Clock) -> bool {
    if !reminder_enabled || state.is_paid(clock) {
        return false;
    }
    match state.last_note_at {
        None => true,
        Some(last) => clock.now() - last >= Duration::days(NOTE_INTERVAL_DAYS),
    }
}

/// Record that the note was shown now.
pub fn mark_shown(state: &mut CoffeeState, clock: &dyn Clock) {
    state.last_note_at = Some(clock.now());
}

/// Mark the current year as paid. Warden trusts the user. The caller must save `state`.
pub fn mark_paid(state: &mut CoffeeState, clock: &dyn Clock) {
    let now = clock.now();
    state.paid_year = Some(now.year());
    state.paid_at = Some(now);
}

/// Storage of [`CoffeeState`] under the `coffee` key of a settings JSON file.
///
/// Other keys of the file stay unchanged. The file path comes from the caller.
#[derive(Debug, Clone)]
pub struct CoffeeStore {
    path: PathBuf,
}

impl CoffeeStore {
    /// Create a store for the settings file at `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The settings file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read_root(&self) -> Result<serde_json::Map<String, serde_json::Value>, CoffeeError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => match serde_json::from_slice(&bytes)? {
                serde_json::Value::Object(m) => Ok(m),
                _ => Err(CoffeeError::Malformed),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Default::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Load the state. A missing file or key gives the default state.
    pub fn load(&self) -> Result<CoffeeState, CoffeeError> {
        match self.read_root()?.remove("coffee") {
            Some(v) => Ok(serde_json::from_value(v)?),
            None => Ok(CoffeeState::default()),
        }
    }

    /// Save the state. The write uses a temporary file and a rename.
    pub fn save(&self, state: &CoffeeState) -> Result<(), CoffeeError> {
        let mut root = self.read_root()?;
        root.insert("coffee".into(), serde_json::to_value(state)?);
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&root)?)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use warden_core::FixedClock;

    fn at(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 12, 0, 0).unwrap()
    }

    #[test]
    fn mark_paid_sets_the_current_year() {
        let clock = FixedClock::new(at(2026, 11, 24));
        let mut st = CoffeeState::default();
        mark_paid(&mut st, &clock);
        assert_eq!(st.paid_year, Some(2026));
        assert_eq!(st.paid_at, Some(at(2026, 11, 24)));
        assert!(st.is_paid(&clock));
    }

    #[test]
    fn paid_year_stops_the_note_and_the_next_year_starts_it() {
        let clock = FixedClock::new(at(2026, 11, 24));
        let mut st = CoffeeState::default();
        assert!(should_show_note(&st, true, &clock));
        mark_paid(&mut st, &clock);
        assert!(!should_show_note(&st, true, &clock));
        clock.set(at(2026, 12, 31));
        assert!(!should_show_note(&st, true, &clock));
        clock.set(at(2027, 1, 1));
        assert!(should_show_note(&st, true, &clock));
    }

    #[test]
    fn seven_day_cadence() {
        let clock = FixedClock::new(at(2026, 11, 24));
        let mut st = CoffeeState::default();
        assert!(should_show_note(&st, true, &clock));
        mark_shown(&mut st, &clock);
        assert!(!should_show_note(&st, true, &clock));
        clock.advance(Duration::days(6) + Duration::hours(23));
        assert!(!should_show_note(&st, true, &clock));
        clock.advance(Duration::hours(1));
        assert!(should_show_note(&st, true, &clock));
    }

    #[test]
    fn reminder_off_never() {
        let clock = FixedClock::new(at(2026, 11, 24));
        assert!(!should_show_note(&CoffeeState::default(), false, &clock));
    }

    #[test]
    fn store_keeps_other_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, r#"{"coffee_reminder":true}"#).unwrap();
        let store = CoffeeStore::new(&path);
        assert_eq!(store.load().unwrap(), CoffeeState::default());
        let st = CoffeeState {
            paid_year: Some(2026),
            paid_at: Some(at(2026, 11, 1)),
            last_note_at: Some(at(2026, 11, 1)),
            ..Default::default()
        };
        store.save(&st).unwrap();
        assert_eq!(store.load().unwrap(), st);
        let raw: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(raw["coffee_reminder"], true);
    }

    #[test]
    fn old_settings_with_extra_fields_still_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            r#"{"coffee":{"paid_year":2026,"old_a":"r1","old_b":"x","old_c":2026,"old_d":"2026-11-01T00:00:00Z","rotations_since_note":2}}"#,
        )
        .unwrap();
        let st = CoffeeStore::new(&path).load().unwrap();
        assert_eq!(st.paid_year, Some(2026));
        assert_eq!(st.rotations_since_note, 2);
        assert!(st.paid_at.is_none());
    }

    #[test]
    fn note_has_the_bare_link_and_the_commands() {
        assert!(NOTE_BODY.contains(COFFEE_URL));
        assert!(NOTE_BODY.contains("awd coffee --pay"));
        assert!(NOTE_BODY.contains("awd coffee --paid"));
    }
}
