//! Authenticated encryption with associated data (spec §54: real AEAD only,
//! never XOR/base64/SHA256-as-crypto per §79).
//!
//! XChaCha20-Poly1305. Associated data binds ciphertext to the package/runtime
//! header so a payload cannot be silently transplanted (spec §27).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::rng::RandomSource;
use crate::version::{KEY_LEN, XNONCE_LEN};

/// A sealed blob: 24-byte nonce prepended to ciphertext+tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sealed {
    pub nonce: [u8; XNONCE_LEN],
    pub ct: Vec<u8>,
}

impl Sealed {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(XNONCE_LEN + self.ct.len());
        v.extend_from_slice(&self.nonce);
        v.extend_from_slice(&self.ct);
        v
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < XNONCE_LEN {
            return Err(CryptoError::Malformed);
        }
        let mut nonce = [0u8; XNONCE_LEN];
        nonce.copy_from_slice(&b[..XNONCE_LEN]);
        Ok(Sealed { nonce, ct: b[XNONCE_LEN..].to_vec() })
    }
}

/// Encrypt `plaintext` under `key`, binding `aad`, drawing the nonce from an
/// injected `RandomSource` (correction pass §8 — this layer makes no OS calls).
/// Random 192-bit XChaCha nonces are safe to generate randomly.
pub fn seal_with<R: RandomSource + ?Sized>(
    rng: &R,
    key: &[u8; KEY_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Sealed> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = rng.array::<XNONCE_LEN>()?;
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::Decrypt)?;
    Ok(Sealed { nonce, ct })
}

/// Convenience wrapper using the OS CSPRNG. Available with the `os-rng`
/// feature; the core sealing logic above has no platform dependency.
#[cfg(feature = "os-rng")]
pub fn seal(key: &[u8; KEY_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Sealed> {
    seal_with(&crate::rng::OsRandom, key, aad, plaintext)
}

/// Decrypt `sealed` under `key`, verifying `aad`. Any tamper (ciphertext, aad,
/// or a wrong key from a failed factor) fails authentication (spec §32: a wrong
/// key — not a bypassed branch — is what the attacker faces).
pub fn open(key: &[u8; KEY_LEN], aad: &[u8], sealed: &Sealed) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let pt = cipher
        .decrypt(XNonce::from_slice(&sealed.nonce), Payload { msg: &sealed.ct, aad })
        .map_err(|_| CryptoError::Decrypt)?;
    Ok(Zeroizing::new(pt))
}
