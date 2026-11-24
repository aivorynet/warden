//! Time source, injectable for tests.

use chrono::{DateTime, Duration, Utc};
use std::sync::Mutex;

/// A source of the current time.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// Return the current time.
    fn now(&self) -> DateTime<Utc>;
}

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// A clock that returns a set time. For tests.
#[derive(Debug)]
pub struct FixedClock(Mutex<DateTime<Utc>>);

impl FixedClock {
    /// Create a clock at `now`.
    pub fn new(now: DateTime<Utc>) -> Self {
        Self(Mutex::new(now))
    }

    /// Set the time.
    pub fn set(&self, now: DateTime<Utc>) {
        *self.0.lock().expect("clock lock") = now;
    }

    /// Move the time forward by `by`.
    pub fn advance(&self, by: Duration) {
        *self.0.lock().expect("clock lock") += by;
    }
}

impl Clock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
        *self.0.lock().expect("clock lock")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_clock_advances() {
        let t = DateTime::from_timestamp(1_000, 0).unwrap();
        let c = FixedClock::new(t);
        c.advance(Duration::seconds(5));
        assert_eq!(c.now().timestamp(), 1_005);
    }
}
