//! Rotation policy, settings and the schedule function.

use crate::Item;
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DAY: u64 = 86_400;

/// Serde helpers: a `Duration` as whole seconds.
pub mod secs {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    /// Serialize as seconds.
    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_secs())
    }

    /// Deserialize from seconds.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        u64::deserialize(d).map(Duration::from_secs)
    }
}

/// Serde helpers: an `Option<Duration>` as whole seconds.
pub mod opt_secs {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    /// Serialize as seconds or null.
    pub fn serialize<S: Serializer>(d: &Option<Duration>, s: S) -> Result<S::Ok, S::Error> {
        match d {
            Some(d) => s.serialize_some(&d.as_secs()),
            None => s.serialize_none(),
        }
    }

    /// Deserialize from seconds or null.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Duration>, D::Error> {
        Ok(Option::<u64>::deserialize(d)?.map(Duration::from_secs))
    }
}

/// Rotation policy of one item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationPolicy {
    /// Rotate automatically.
    pub auto_rotate: bool,
    /// Rotation interval. `None` uses the global default.
    #[serde(with = "opt_secs")]
    pub interval: Option<Duration>,
    /// Rotate this long before the end date.
    #[serde(with = "secs")]
    pub lead_time: Duration,
    /// Wait this long before the old token is revoked (`Overlap` class).
    #[serde(with = "secs")]
    pub grace: Duration,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            auto_rotate: true,
            interval: None,
            lead_time: Duration::from_secs(3 * DAY),
            grace: Duration::from_secs(DAY),
        }
    }
}

/// Global settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    /// Default rotation interval.
    #[serde(with = "secs")]
    pub default_interval: Duration,
    /// Show the weekly coffee reminder.
    pub coffee_reminder: bool,
    /// Cache the vault key in the OS keychain.
    pub keychain_cache: bool,
    /// Unlock with the OS user check (Windows Hello, Touch ID, polkit) instead of the password.
    ///
    /// Only valid when `keychain_cache` is on. Lock then keeps the cached key (soft lock).
    #[serde(default)]
    pub quick_unlock: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            default_interval: Duration::from_secs(30 * DAY),
            coffee_reminder: true,
            keychain_cache: true,
            quick_unlock: false,
        }
    }
}

fn delta(d: Duration) -> TimeDelta {
    TimeDelta::from_std(d).unwrap_or(TimeDelta::MAX)
}

/// Return the next rotation time of `item`, or `None` when auto-rotate is off.
///
/// It is the earlier of (last rotation or creation + interval) and (end date - lead time).
/// `now` is not used for the result. Callers compare the result with the current time.
pub fn next_rotation(
    item: &Item,
    settings: &Settings,
    _now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    if !item.policy.auto_rotate {
        return None;
    }
    let base = item.rotated_at.unwrap_or(item.created_at);
    let interval = item.policy.interval.unwrap_or(settings.default_interval);
    let by_interval = base.checked_add_signed(delta(interval));
    let by_expiry = item
        .expires_at
        .and_then(|e| e.checked_sub_signed(delta(item.policy.lead_time)));
    match (by_interval, by_expiry) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeviceId, ItemId, ItemKind, McpPolicy, ProviderKind, ProviderRef};

    fn t(day: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(day * 86_400, 0).unwrap()
    }

    fn item() -> Item {
        Item {
            id: ItemId::new(),
            name: "n".into(),
            slug: "n".into(),
            kind: ItemKind::Admin,
            provider: ProviderRef {
                kind: ProviderKind::Manual,
                config: serde_json::Value::Null,
            },
            provider_token_id: None,
            expires_at: None,
            created_at: t(100),
            rotated_at: None,
            policy: RotationPolicy::default(),
            sinks: vec![],
            mcp: McpPolicy::default(),
            rotator_device: DeviceId::new(),
            tags: vec![],
        }
    }

    #[test]
    fn default_interval_from_created() {
        let s = Settings::default();
        assert_eq!(next_rotation(&item(), &s, t(100)), Some(t(130)));
    }

    #[test]
    fn rotated_at_beats_created() {
        let mut i = item();
        i.rotated_at = Some(t(110));
        assert_eq!(next_rotation(&i, &Settings::default(), t(0)), Some(t(140)));
    }

    #[test]
    fn item_interval_overrides_default() {
        let mut i = item();
        i.policy.interval = Some(Duration::from_secs(7 * DAY));
        assert_eq!(next_rotation(&i, &Settings::default(), t(0)), Some(t(107)));
    }

    #[test]
    fn expiry_minus_lead_wins_when_earlier() {
        let mut i = item();
        i.expires_at = Some(t(120));
        i.policy.lead_time = Duration::from_secs(5 * DAY);
        assert_eq!(next_rotation(&i, &Settings::default(), t(0)), Some(t(115)));
    }

    #[test]
    fn interval_wins_when_earlier_than_expiry() {
        let mut i = item();
        i.expires_at = Some(t(400));
        assert_eq!(next_rotation(&i, &Settings::default(), t(0)), Some(t(130)));
    }

    #[test]
    fn none_when_auto_rotate_off() {
        let mut i = item();
        i.policy.auto_rotate = false;
        assert_eq!(next_rotation(&i, &Settings::default(), t(0)), None);
    }

    #[test]
    fn quick_unlock_is_off_by_default_and_old_json_loads() {
        assert!(!Settings::default().quick_unlock);
        let old = r#"{"default_interval":2592000,"coffee_reminder":true,"keychain_cache":true}"#;
        let s: Settings = serde_json::from_str(old).unwrap();
        assert!(!s.quick_unlock && s.keychain_cache);
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = RotationPolicy::default();
        let j = serde_json::to_string(&p).unwrap();
        assert_eq!(serde_json::from_str::<RotationPolicy>(&j).unwrap(), p);
    }
}
