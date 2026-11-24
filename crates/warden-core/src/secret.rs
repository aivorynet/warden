//! Secret value type. The value never appears in `Debug` or `Display`.

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serializer};
use std::fmt;

/// A secret string. Memory is zeroized on drop.
pub struct SecretValue(SecretString);

impl SecretValue {
    /// Wrap a string as a secret.
    pub fn new(value: impl Into<String>) -> Self {
        Self(SecretString::from(value.into()))
    }

    /// Expose the secret. Call only where the value must leave the type.
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }

    /// Compare with another value in constant time for equal lengths.
    pub fn ct_eq(&self, other: &SecretValue) -> bool {
        let (a, b) = (self.expose().as_bytes(), other.expose().as_bytes());
        if a.len() != b.len() {
            return false;
        }
        a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
    }
}

impl Clone for SecretValue {
    fn clone(&self) -> Self {
        Self::new(self.expose())
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue([REDACTED])")
    }
}

impl From<String> for SecretValue {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for SecretValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(Self::new)
    }
}

/// Explicit serialization of a secret. Use with `#[serde(serialize_with = "expose::serialize")]`.
/// Only the vault and the IPC client side use it.
pub mod expose {
    use super::*;

    /// Serialize the secret value as a plain string.
    pub fn serialize<S: Serializer>(v: &SecretValue, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(v.expose())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_hides_value() {
        let s = SecretValue::new("hunter2");
        assert!(!format!("{s:?}").contains("hunter2"));
        assert!(s.ct_eq(&s.clone()));
        assert!(!s.ct_eq(&SecretValue::new("hunter3")));
    }
}
