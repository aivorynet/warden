//! The coffee pledge, the ticket number and the notes at moments of value.
//!
//! This follows Hopover: the user signs a pledge at first run, a stable ticket number names the
//! install, and the app reminds at moments when it just did useful work. Warden adds a yearly
//! cycle: a signed receipt covers one calendar year.

use crate::{COFFEE_URL, CoffeeState, NOTE_INTERVAL_DAYS};
use chrono::{Datelike, Duration};
use warden_core::Clock;

/// Text of the pledge that the user signs at first run.
pub const PLEDGE_TEXT: &str = "I promise: if Warden saves me from one expired token, Paul gets his coffee. A promise is a promise, even on the internet.";
/// Price label shown next to every coffee button.
pub const PRICE_LABEL: &str = "pay what you want, 5 EUR suggested";
/// Text shown when no receipt covers the current year.
pub const HONEST_LINE: &str = "No account, no trial, no locked features. Warden checks a signed receipt offline, and it never stops a rotation.";
/// Text shown after a valid receipt for the current year.
pub const THANKS_TEXT: &str =
    "Thanks for the coffee, genuinely. You made my day. If something breaks, send me the log.";
/// Source code link.
pub const SOURCE_URL: &str = "https://github.com/aivorynet/warden";
/// Review link. Placeholder until the listing exists; callers show nothing for a value that starts with `[`.
pub const REVIEW_URL: &str = "[REVIEW-URL]";

/// A moment when Warden may show a coffee note.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Moment {
    /// The first rotation that completed on this install.
    FirstRotation,
    /// The weekly check of the daemon.
    Weekly,
}

/// A note to show as a desktop notification, on CLI stderr or in the desktop app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    /// Short title.
    pub title: String,
    /// Body text with the link.
    pub body: String,
}

/// Ticket number of this install, for example `AIVW-2026-6909`. It stays the same for a device and year.
pub fn ticket_no(device_id: &str, year: i32) -> String {
    // FNV-1a: stable across platforms and Rust versions.
    let mut h: u32 = 0x811c_9dc5;
    for b in device_id.as_bytes() {
        h ^= u32::from(*b);
        h = h.wrapping_mul(0x0100_0193);
    }
    format!("AIVW-{year}-{:04}", h % 10_000)
}

/// Return true when the user signed the pledge.
pub fn is_pledged(state: &CoffeeState) -> bool {
    state.pledge_signed_at.is_some()
}

/// Record the signed pledge.
pub fn sign_pledge(state: &mut CoffeeState, user: &str, clock: &dyn Clock) {
    state.pledge_signed_at = Some(clock.now());
    state.pledge_signed_by = Some(user.to_owned());
}

/// Record one successful rotation.
pub fn record_rotation(state: &mut CoffeeState) {
    state.rotations_since_note = state.rotations_since_note.saturating_add(1);
}

/// Return the note for `moment`, or `None` when no note is due.
///
/// Rules: no note when the reminder is off or a receipt covers the current year. The first
/// completed rotation gets one note per install. The weekly note needs 7 days since the last
/// note. A returned note is recorded in `state`, so the caller must save `state` after it.
pub fn take_note(
    state: &mut CoffeeState,
    moment: Moment,
    reminder_enabled: bool,
    clock: &dyn Clock,
) -> Option<Note> {
    if !reminder_enabled || state.is_paid(clock) {
        return None;
    }
    let now = clock.now();
    let year = now.year();
    let note = match moment {
        Moment::FirstRotation if !state.first_rotation_noted => {
            state.first_rotation_noted = true;
            Note {
                title: "Your first token rotated on its own".to_owned(),
                body: format!(
                    "Warden just did the boring part for you. A coffee for {year} keeps it free and open source ({PRICE_LABEL}): {COFFEE_URL}"
                ),
            }
        }
        Moment::Weekly => {
            let due = state
                .last_note_at
                .is_none_or(|last| now - last >= Duration::days(NOTE_INTERVAL_DAYS));
            if !due {
                return None;
            }
            let n = state.rotations_since_note;
            let lead = if n == 0 {
                "Warden watched your tokens this week.".to_owned()
            } else if n == 1 {
                "Warden rotated 1 token this week.".to_owned()
            } else {
                format!("Warden rotated {n} tokens this week.")
            };
            Note {
                title: format!("A coffee for {year}?"),
                body: format!(
                    "{lead} One coffee a year stops this note ({PRICE_LABEL}): {COFFEE_URL}"
                ),
            }
        }
        Moment::FirstRotation => return None,
    };
    state.last_note_at = Some(now);
    state.rotations_since_note = 0;
    Some(note)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use warden_core::FixedClock;

    fn clock() -> FixedClock {
        FixedClock::new(Utc.with_ymd_and_hms(2026, 11, 24, 10, 0, 0).unwrap())
    }

    #[test]
    fn ticket_is_stable() {
        let a = ticket_no("dev-1", 2026);
        assert_eq!(a, ticket_no("dev-1", 2026));
        assert!(a.starts_with("AIVW-2026-") && a.len() == 14);
    }

    #[test]
    fn pledge_is_recorded() {
        let mut s = CoffeeState::default();
        assert!(!is_pledged(&s));
        sign_pledge(&mut s, "paul", &clock());
        assert!(is_pledged(&s));
        assert_eq!(s.pledge_signed_by.as_deref(), Some("paul"));
    }

    #[test]
    fn first_rotation_once_then_weekly_cadence() {
        let c = clock();
        let mut s = CoffeeState::default();
        assert!(take_note(&mut s, Moment::FirstRotation, true, &c).is_some());
        assert!(take_note(&mut s, Moment::FirstRotation, true, &c).is_none());
        assert!(take_note(&mut s, Moment::Weekly, true, &c).is_none());
        record_rotation(&mut s);
        record_rotation(&mut s);
        c.advance(Duration::days(7));
        let n = take_note(&mut s, Moment::Weekly, true, &c).expect("weekly note");
        assert!(n.body.contains("rotated 2 tokens"));
        assert_eq!(s.rotations_since_note, 0);
    }

    #[test]
    fn paid_or_off_means_silence() {
        let c = clock();
        let mut s = CoffeeState::default();
        assert!(take_note(&mut s, Moment::Weekly, false, &c).is_none());
        s.paid_year = Some(2026);
        assert!(take_note(&mut s, Moment::FirstRotation, true, &c).is_none());
        assert!(take_note(&mut s, Moment::Weekly, true, &c).is_none());
    }

    #[test]
    fn new_year_needs_new_receipt() {
        let c = FixedClock::new(Utc.with_ymd_and_hms(2027, 1, 2, 9, 0, 0).unwrap());
        let mut s = CoffeeState {
            paid_year: Some(2026),
            ..Default::default()
        };
        assert!(take_note(&mut s, Moment::Weekly, true, &c).is_some());
    }
}
