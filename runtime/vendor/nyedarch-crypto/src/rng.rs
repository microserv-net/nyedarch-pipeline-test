//! Randomness as an *injected interface* (correction pass §8).
//!
//! `nyedarch-crypto` is the smallest auditable confidentiality boundary: no I/O,
//! no platform dependency. Randomness is therefore a trait the caller supplies,
//! not an OS call this layer makes on its own. Two consequences:
//!
//! 1. deterministic test vectors are possible without weakening production code
//!    (a fixed `RandomSource` in tests, never compiled into a release path);
//! 2. the OS CSPRNG binding lives behind the default `os-rng` feature, so the
//!    core can be audited and built with zero platform surface.

use crate::error::{CryptoError, Result};

/// Source of cryptographically secure random bytes.
pub trait RandomSource {
    /// Fill `buf`. MUST fail rather than produce low-quality bytes (spec §29:
    /// fail closed; §36: never silently downgrade).
    fn fill(&self, buf: &mut [u8]) -> Result<()>;

    fn array<const N: usize>(&self) -> Result<[u8; N]> {
        let mut b = [0u8; N];
        self.fill(&mut b)?;
        Ok(b)
    }
}

/// OS CSPRNG. Available only with the `os-rng` feature (default on for the
/// builder/runtime; off when auditing the crate in isolation).
#[cfg(feature = "os-rng")]
pub struct OsRandom;

#[cfg(feature = "os-rng")]
impl RandomSource for OsRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<()> {
        getrandom::getrandom(buf).map_err(|_| CryptoError::Rng)
    }
}

#[cfg(feature = "os-rng")]
pub fn os() -> OsRandom {
    OsRandom
}

/// Deterministic counter source. **Test/vector use only** — it is explicitly
/// not a `RandomSource` for production paths, and is compiled out of releases.
#[cfg(test)]
pub struct FixedSource(pub u8);

#[cfg(test)]
impl RandomSource for FixedSource {
    fn fill(&self, buf: &mut [u8]) -> Result<()> {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = self.0.wrapping_add(i as u8);
        }
        Ok(())
    }
}

#[cfg(not(feature = "os-rng"))]
#[allow(dead_code)]
fn _unused(_e: CryptoError) {}
