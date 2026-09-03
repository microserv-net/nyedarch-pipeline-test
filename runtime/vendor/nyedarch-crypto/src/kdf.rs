//! Key derivation primitives.
//!
//! - Argon2id for the memory-hard passphrase factor (spec §18).
//! - HKDF-SHA512 for domain-separated expansion/composition (spec §25/§54).
//!
//! Passphrase-derived material is returned inside `Zeroizing` and never logged
//! or persisted in plaintext (spec §18/§55/§57).

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::version::KEY_LEN;

/// Versioned Argon2id parameters (spec §18: versioned, benchmarked, no DoS).
/// These defaults are deliberately conservative for an interactive desktop
/// unlock; the builder benchmarks and may raise them per package. Encoded into
/// the package header so the runtime reproduces the exact derivation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2Params {
    /// Memory cost in KiB.
    pub m_cost: u32,
    /// Time cost (iterations).
    pub t_cost: u32,
    /// Degree of parallelism.
    pub p_cost: u32,
}

impl Argon2Params {
    /// Interactive default: 256 MiB, 3 passes, 1 lane. ~sub-second on modern
    /// desktop, forces large memory on an attacker per guess.
    pub const INTERACTIVE: Argon2Params = Argon2Params { m_cost: 256 * 1024, t_cost: 3, p_cost: 1 };

    /// Guardrails against accidental denial-of-service settings (spec §18).
    pub fn validate(&self) -> Result<()> {
        // Argon2 requires m_cost >= 8*p_cost and p_cost >= 1.
        if self.p_cost == 0 || self.t_cost == 0 {
            return Err(CryptoError::Param);
        }
        if self.m_cost < 8 * self.p_cost {
            return Err(CryptoError::Param);
        }
        // Refuse absurd memory (> 4 GiB) that would DoS a legitimate unlock.
        if self.m_cost > 4 * 1024 * 1024 {
            return Err(CryptoError::Param);
        }
        Ok(())
    }
}

/// Derive the passphrase factor contribution with Argon2id.
///
/// `salt` is per-package random (spec §18). Output is 32 bytes of key material,
/// zeroized on drop.
pub fn passphrase_contribution(
    passphrase: &[u8],
    salt: &[u8],
    params: Argon2Params,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    params.validate()?;
    if salt.len() < 8 {
        return Err(CryptoError::Param);
    }
    let p = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|_| CryptoError::Kdf)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(passphrase, salt, out.as_mut())
        .map_err(|_| CryptoError::Kdf)?;
    Ok(out)
}

/// HKDF-SHA512 extract+expand into a fixed 32-byte key.
///
/// `salt` binds to the package; `info` is the domain-separated context string.
pub fn hkdf_key(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let hk = Hkdf::<Sha512>::new(Some(salt), ikm);
    let mut okm = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(info, okm.as_mut()).map_err(|_| CryptoError::Kdf)?;
    Ok(okm)
}
