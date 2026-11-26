//! Key derivation, the Secret Key, and authenticated encryption.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Sha256;
use std::fmt;
use std::str::FromStr;
use warden_core::{Result, WardenError};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Crockford base32 alphabet.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// HKDF info string for the key-encryption key.
const KEK_INFO: &[u8] = b"aivory-warden/v1/kek";

/// Build a vault error.
pub(crate) fn verr(msg: impl Into<String>) -> WardenError {
    WardenError::Vault(msg.into())
}

/// Return `N` random bytes.
pub(crate) fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::rng().fill_bytes(&mut b);
    b
}

/// Return `N` random bytes in a buffer that zeroizes on drop.
pub(crate) fn random_zeroizing<const N: usize>() -> Zeroizing<[u8; N]> {
    let mut b = Zeroizing::new([0u8; N]);
    rand::rng().fill_bytes(&mut *b);
    b
}

/// Argon2id parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_kib: u32,
    /// Iterations.
    pub t: u32,
    /// Parallel lanes.
    pub p: u32,
}

impl KdfParams {
    /// Production parameters: 64 MiB, 3 iterations, 4 lanes.
    pub const DEFAULT: KdfParams = KdfParams {
        m_kib: 64 * 1024,
        t: 3,
        p: 4,
    };

    /// Custom parameters. Use low values in tests only.
    pub fn new(m_kib: u32, t: u32, p: u32) -> Self {
        Self { m_kib, t, p }
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The Secret Key: 125 random bits, shown as `A3-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; 16]);

impl SecretKey {
    /// Generate a new random Secret Key.
    pub fn generate() -> Self {
        let mut k = Self([0u8; 16]);
        rand::rng().fill_bytes(&mut k.0);
        k.0[0] &= 0x1F; // 125 bits: the format has 25 base32 characters
        k
    }

    /// Build a Secret Key from raw bytes. The top 3 bits must be zero.
    pub fn from_bytes(b: [u8; 16]) -> Result<Self> {
        if b[0] > 0x1F {
            return Err(verr("secret key has more than 125 bits"));
        }
        Ok(Self(b))
    }

    /// Return the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey([REDACTED])")
    }
}

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v = u128::from_be_bytes(self.0);
        f.write_str("A3")?;
        for i in 0..25 {
            if i % 5 == 0 {
                f.write_str("-")?;
            }
            let idx = ((v >> ((24 - i) * 5)) & 31) as usize;
            write!(f, "{}", ALPHABET[idx] as char)?;
        }
        Ok(())
    }
}

impl FromStr for SecretKey {
    type Err = WardenError;
    fn from_str(s: &str) -> Result<Self> {
        let up: Zeroizing<String> = Zeroizing::new(
            s.chars()
                .filter(|c| !c.is_whitespace() && *c != '-')
                .map(|c| match c.to_ascii_uppercase() {
                    'O' => '0',
                    'I' | 'L' => '1',
                    o => o,
                })
                .collect(),
        );
        let body = up
            .strip_prefix("A3")
            .ok_or_else(|| verr("secret key must start with A3"))?;
        if body.len() != 25 {
            return Err(verr("secret key must have 25 characters after A3"));
        }
        let mut v = Zeroizing::new(0u128);
        for c in body.bytes() {
            let d = ALPHABET
                .iter()
                .position(|a| *a == c)
                .ok_or_else(|| verr("secret key has an invalid character"))?;
            *v = (*v << 5) | d as u128;
        }
        Ok(Self(v.to_be_bytes()))
    }
}

/// Derive the key-encryption key: Argon2id over the password, then HKDF-SHA256 with the Secret Key.
pub fn derive_kek(
    password: &[u8],
    secret_key: &SecretKey,
    salt: &[u8],
    params: &KdfParams,
) -> Result<Zeroizing<[u8; 32]>> {
    let p = Params::new(params.m_kib, params.t, params.p, Some(32))
        .map_err(|e| verr(format!("bad kdf params: {e}")))?;
    let mut pwd = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
        .hash_password_into(password, salt, &mut *pwd)
        .map_err(|e| verr(format!("argon2 failed: {e}")))?;
    let hk = Hkdf::<Sha256>::new(Some(secret_key.as_bytes()), &*pwd);
    let mut kek = Zeroizing::new([0u8; 32]);
    hk.expand(KEK_INFO, &mut *kek)
        .map_err(|_| verr("hkdf expand failed"))?;
    Ok(kek)
}

/// Encrypt with XChaCha20-Poly1305. Returns `(nonce, ciphertext)`.
pub(crate) fn seal(key: &[u8; 32], aad: &[u8], msg: &[u8]) -> Result<([u8; 24], Vec<u8>)> {
    let nonce: [u8; 24] = random();
    let c = XChaCha20Poly1305::new_from_slice(key).map_err(|_| verr("bad key"))?;
    let ct = c
        .encrypt(&XNonce::from(nonce), Payload { msg, aad })
        .map_err(|_| verr("encryption failed"))?;
    Ok((nonce, ct))
}

/// Decrypt with XChaCha20-Poly1305.
pub(crate) fn open(
    key: &[u8; 32],
    aad: &[u8],
    nonce: &[u8; 24],
    ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let c = XChaCha20Poly1305::new_from_slice(key).map_err(|_| verr("bad key"))?;
    c.decrypt(&XNonce::from(*nonce), Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| verr("decryption failed"))
}

/// Bytes that serialize as a lowercase hex string.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Hex(pub Vec<u8>);

impl Hex {
    /// Convert to a fixed-size array.
    pub fn arr<const N: usize>(&self) -> Result<[u8; N]> {
        self.0
            .as_slice()
            .try_into()
            .map_err(|_| verr(format!("expected {N} bytes")))
    }
}

/// Encode bytes as lowercase hex.
pub(crate) fn hex_enc(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Serialize for Hex {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&hex_enc(&self.0))
    }
}

impl<'de> Deserialize<'de> for Hex {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(serde::de::Error::custom("bad hex"));
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .collect::<std::result::Result<Vec<u8>, _>>()
            .map(Hex)
            .map_err(|_| serde::de::Error::custom("bad hex"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_rejects_sign_characters() {
        assert!(serde_json::from_str::<Hex>("\"+1\"").is_err());
        assert!(serde_json::from_str::<Hex>("\"-1\"").is_err());
        assert_eq!(
            serde_json::from_str::<Hex>("\"0aFf\"").unwrap().0,
            vec![10, 255]
        );
    }

    #[test]
    fn secret_key_roundtrip() {
        let k = SecretKey::generate();
        let s = k.to_string();
        assert_eq!(s.len(), 2 + 5 * 6);
        assert!(s.starts_with("A3-"));
        assert_eq!(s.parse::<SecretKey>().unwrap(), k);
        assert_eq!(s.to_lowercase().parse::<SecretKey>().unwrap(), k);
        assert!("A3-ABCDE".parse::<SecretKey>().is_err());
        assert!(
            "B4-00000-00000-00000-00000-00000"
                .parse::<SecretKey>()
                .is_err()
        );
    }

    #[test]
    fn secret_key_fixed_format() {
        let mut b = [0u8; 16];
        b[15] = 1;
        let k = SecretKey::from_bytes(b).unwrap();
        assert_eq!(k.to_string(), "A3-00000-00000-00000-00000-00001");
    }

    #[test]
    fn kdf_known_answer() {
        let sk: SecretKey = "A3-00000-00000-00000-00000-0000Z".parse().unwrap();
        let kek = derive_kek(
            b"correct horse battery staple",
            &sk,
            b"0123456789abcdef",
            &KdfParams::new(32, 2, 1),
        )
        .unwrap();
        assert_eq!(
            hex_enc(&*kek),
            "226d6bcb67dfe280769c5e709136a79b778c26cd45542eeb1cbb57d0ea89788c"
        );
    }
}
