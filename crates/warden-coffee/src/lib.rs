//! Coffee receipts and the weekly reminder note.
//!
//! A receipt is `aivw-receipt-<base64url(payload)>.<base64url(ed25519 signature)>`. The payload
//! is JSON `{year, receipt_id, issued}`. The app verifies the receipt offline with an embedded
//! public key. The reminder never blocks any other work.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Datelike, Duration, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use warden_core::Clock;

mod pledge;
pub use pledge::*;

/// Prefix of a receipt code.
pub const RECEIPT_PREFIX: &str = "aivw-receipt-";
/// Link where the user pays for a coffee.
pub const COFFEE_URL: &str = "https://buy.stripe.com/5kQbJ3csm21Xfz64DhdjO00";
/// Title of the reminder note.
pub const NOTE_TITLE: &str = "Aivory Warden is free. A coffee keeps it that way.";
/// Body of the reminder note.
pub const NOTE_BODY: &str = "If Warden saves you time, buy the developer a coffee: https://buy.stripe.com/5kQbJ3csm21Xfz64DhdjO00. Paste the receipt code in Settings or run `awd coffee --receipt <code>` to stop this note for the year. Turn the note off in Settings.";
/// Minimum time between two notes.
pub const NOTE_INTERVAL_DAYS: i64 = 7;

/// Production public key of the receipt signer.
///
/// TODO(Paul): replace this placeholder with the public key of the production signing key pair.
/// While the key is all zero, no production receipt verifies.
pub const PRODUCTION_PUBLIC_KEY: [u8; 32] = [0u8; 32];

/// Error of receipt verification or storage.
#[derive(Debug, thiserror::Error)]
pub enum CoffeeError {
    /// The code has no valid shape.
    #[error("malformed receipt code")]
    Malformed,
    /// The signature does not match the payload or the key.
    #[error("receipt signature is not valid")]
    BadSignature,
    /// The receipt is for another year.
    #[error("receipt is for year {receipt}, not {current}")]
    WrongYear {
        /// Year in the receipt.
        receipt: i32,
        /// Current year.
        current: i32,
    },
    /// A file failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// A JSON failure.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Signed content of a receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// Year that the receipt covers.
    pub year: i32,
    /// Unique receipt id.
    pub receipt_id: String,
    /// Time of issue.
    pub issued: DateTime<Utc>,
}

/// Verify `code` with the embedded production key.
pub fn verify(code: &str) -> Result<Receipt, CoffeeError> {
    verify_with_key(code, &PRODUCTION_PUBLIC_KEY)
}

/// Verify the signature of `code` with `pubkey` and return the payload.
///
/// This function does not check the year. Use [`apply_receipt_with_key`] for that.
pub fn verify_with_key(code: &str, pubkey: &[u8; 32]) -> Result<Receipt, CoffeeError> {
    let rest = code
        .trim()
        .strip_prefix(RECEIPT_PREFIX)
        .ok_or(CoffeeError::Malformed)?;
    let (payload_b64, sig_b64) = rest.split_once('.').ok_or(CoffeeError::Malformed)?;
    let payload = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| CoffeeError::Malformed)?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| CoffeeError::Malformed)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| CoffeeError::Malformed)?;
    let key = VerifyingKey::from_bytes(pubkey).map_err(|_| CoffeeError::BadSignature)?;
    key.verify_strict(&payload, &sig)
        .map_err(|_| CoffeeError::BadSignature)?;
    serde_json::from_slice(&payload).map_err(|_| CoffeeError::Malformed)
}

/// Coffee state in the local settings file. It is not synced.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CoffeeState {
    /// Year of the valid receipt, if any.
    pub paid_year: Option<i32>,
    /// Id of the valid receipt, if any.
    pub receipt_id: Option<String>,
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
    /// Return true when a receipt covers the current year.
    pub fn is_paid(&self, clock: &dyn Clock) -> bool {
        self.paid_year == Some(clock.now().year())
    }
}

/// Return true when the reminder note is due now.
///
/// The note is due when the reminder is on, no receipt covers the current year, and the last
/// note is at least 7 days old (or there was none).
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

/// Verify `code` with the production key and store it in `state`.
pub fn apply_receipt(
    state: &mut CoffeeState,
    code: &str,
    clock: &dyn Clock,
) -> Result<Receipt, CoffeeError> {
    apply_receipt_with_key(state, code, &PRODUCTION_PUBLIC_KEY, clock)
}

/// Verify `code` with `pubkey`, require the current year, and store it in `state`.
pub fn apply_receipt_with_key(
    state: &mut CoffeeState,
    code: &str,
    pubkey: &[u8; 32],
    clock: &dyn Clock,
) -> Result<Receipt, CoffeeError> {
    let receipt = verify_with_key(code, pubkey)?;
    let current = clock.now().year();
    if receipt.year != current {
        return Err(CoffeeError::WrongYear {
            receipt: receipt.year,
            current,
        });
    }
    state.paid_year = Some(receipt.year);
    state.receipt_id = Some(receipt.receipt_id.clone());
    Ok(receipt)
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
    use ed25519_dalek::{Signer, SigningKey};
    use warden_core::FixedClock;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn at(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 12, 0, 0).unwrap()
    }

    fn make(sk: &SigningKey, year: i32) -> String {
        let payload = serde_json::to_vec(&Receipt {
            year,
            receipt_id: "r_test_1".into(),
            issued: at(year, 1, 5),
        })
        .unwrap();
        let sig = sk.sign(&payload);
        format!(
            "{RECEIPT_PREFIX}{}.{}",
            URL_SAFE_NO_PAD.encode(&payload),
            URL_SAFE_NO_PAD.encode(sig.to_bytes())
        )
    }

    #[test]
    fn valid_receipt() {
        let sk = key(1);
        let pk = sk.verifying_key().to_bytes();
        let clock = FixedClock::new(at(2026, 11, 24));
        let mut st = CoffeeState::default();
        let r = apply_receipt_with_key(&mut st, &make(&sk, 2026), &pk, &clock).unwrap();
        assert_eq!(r.receipt_id, "r_test_1");
        assert_eq!(st.paid_year, Some(2026));
        assert_eq!(st.receipt_id.as_deref(), Some("r_test_1"));
        assert!(!should_show_note(&st, true, &clock));
    }

    #[test]
    fn wrong_year() {
        let sk = key(1);
        let pk = sk.verifying_key().to_bytes();
        let clock = FixedClock::new(at(2026, 11, 24));
        let mut st = CoffeeState::default();
        let err = apply_receipt_with_key(&mut st, &make(&sk, 2025), &pk, &clock).unwrap_err();
        assert!(matches!(
            err,
            CoffeeError::WrongYear {
                receipt: 2025,
                current: 2026
            }
        ));
        assert_eq!(st, CoffeeState::default());
        // A paid year from the past does not count in a later year.
        st.paid_year = Some(2026);
        clock.set(at(2027, 1, 2));
        assert!(should_show_note(&st, true, &clock));
    }

    #[test]
    fn tampered_payload() {
        let sk = key(1);
        let pk = sk.verifying_key().to_bytes();
        let code = make(&sk, 2025);
        let (_, sig) = code.split_once('.').unwrap();
        let forged = serde_json::to_vec(&Receipt {
            year: 2026,
            receipt_id: "r_test_1".into(),
            issued: at(2025, 1, 5),
        })
        .unwrap();
        let tampered = format!("{RECEIPT_PREFIX}{}.{sig}", URL_SAFE_NO_PAD.encode(forged));
        assert!(matches!(
            verify_with_key(&tampered, &pk),
            Err(CoffeeError::BadSignature)
        ));
        assert!(matches!(
            verify_with_key("aivw-receipt-nodot", &pk),
            Err(CoffeeError::Malformed)
        ));
        assert!(matches!(
            verify_with_key("garbage", &pk),
            Err(CoffeeError::Malformed)
        ));
    }

    #[test]
    fn wrong_key() {
        let code = make(&key(1), 2026);
        let other = key(2).verifying_key().to_bytes();
        assert!(matches!(
            verify_with_key(&code, &other),
            Err(CoffeeError::BadSignature)
        ));
        // The all-zero placeholder key never verifies.
        assert!(verify(&code).is_err());
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
            receipt_id: Some("x".into()),
            last_note_at: Some(at(2026, 11, 1)),
            ..Default::default()
        };
        store.save(&st).unwrap();
        assert_eq!(store.load().unwrap(), st);
        let raw: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(raw["coffee_reminder"], true);
    }
}
