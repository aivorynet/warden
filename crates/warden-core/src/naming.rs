//! Token naming: provider token names and `aivw_` client tokens.

use crate::{Result, SecretValue, WardenError};
use chrono::NaiveDate;
use rand::Rng;

/// Token prefix.
pub const PREFIX: &str = "aivw_";
const ALPHABET: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const BODY_LEN: usize = 32;
const CRC_LEN: usize = 6;

/// Name for a token that Warden creates at a provider: `aivw_<slug>_<yyyymmdd>`.
pub fn provider_token_name(slug: &str, date: NaiveDate) -> String {
    format!("{PREFIX}{slug}_{}", date.format("%Y%m%d"))
}

fn base62_fixed(mut n: u64, len: usize) -> String {
    let mut out = vec![b'0'; len];
    for slot in out.iter_mut().rev() {
        *slot = ALPHABET[(n % 62) as usize];
        n /= 62;
    }
    String::from_utf8(out).expect("ascii alphabet")
}

fn checksum(body: &str) -> String {
    base62_fixed(u64::from(crc32fast::hash(body.as_bytes())), CRC_LEN)
}

/// A Warden-issued client or pairing token: `aivw_<base62 x32>_<crc32 base62 x6>`.
#[derive(Debug, Clone)]
pub struct ClientToken(SecretValue);

impl ClientToken {
    /// Generate a new random token.
    pub fn generate() -> Self {
        let mut rng = rand::rng();
        let body: String = (0..BODY_LEN)
            .map(|_| ALPHABET[rng.random_range(0..62)] as char)
            .collect();
        let crc = checksum(&body);
        Self(SecretValue::new(format!("{PREFIX}{body}_{crc}")))
    }

    /// Parse and validate a token string (prefix, length, alphabet, checksum).
    pub fn parse(s: &str) -> Result<Self> {
        let bad = || WardenError::Config("invalid client token".into());
        let rest = s.strip_prefix(PREFIX).ok_or_else(bad)?;
        let (body, crc) = rest.split_once('_').ok_or_else(bad)?;
        let ok_chars = |x: &str| x.bytes().all(|b| ALPHABET.contains(&b));
        if body.len() != BODY_LEN || crc.len() != CRC_LEN || !ok_chars(body) || !ok_chars(crc) {
            return Err(bad());
        }
        if checksum(body) != crc {
            return Err(bad());
        }
        Ok(Self(SecretValue::new(s)))
    }

    /// The token as a secret value.
    pub fn secret(&self) -> &SecretValue {
        &self.0
    }

    /// The token string. Expose only to hand it to the client.
    pub fn expose(&self) -> &str {
        self.0.expose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_format() {
        let d = NaiveDate::from_ymd_opt(2026, 11, 3).unwrap();
        assert_eq!(provider_token_name("deploy", d), "aivw_deploy_20261103");
    }

    #[test]
    fn generate_parse_roundtrip() {
        let t = ClientToken::generate();
        assert_eq!(t.expose().len(), 5 + 32 + 1 + 6);
        let p = ClientToken::parse(t.expose()).unwrap();
        assert_eq!(p.expose(), t.expose());
        assert_ne!(ClientToken::generate().expose(), t.expose());
    }

    #[test]
    fn rejects_tampering() {
        let t = ClientToken::generate();
        let mut s = t.expose().to_string();
        let i = 6;
        let c = if s.as_bytes()[i] == b'a' { "b" } else { "a" };
        s.replace_range(i..=i, c);
        assert!(ClientToken::parse(&s).is_err());
        assert!(ClientToken::parse("aivw_short_x").is_err());
        assert!(ClientToken::parse("xxxx_abc").is_err());
        assert!(ClientToken::parse(&t.expose()[1..]).is_err());
    }

    #[test]
    fn debug_hides_token() {
        let t = ClientToken::generate();
        assert!(!format!("{t:?}").contains(&t.expose()[5..15]));
    }
}
