//! Typed, non-leaking errors (spec §57, §60).
//!
//! Error variants deliberately do NOT carry secret material, coordinates,
//! passphrases, or per-gate authorization results — in normal runtime mode the
//! caller collapses all of these to a single "authorization failed" (spec §51).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("authorization failed")] // generic; not an oracle
    Authorization,
    #[error("authenticated decryption failed")]
    Decrypt,
    #[error("key derivation failed")]
    Kdf,
    #[error("unsupported or unknown crypto version: {0}")]
    UnsupportedVersion(u16),
    #[error("malformed input")]
    Malformed,
    #[error("os csprng failure")]
    Rng,
    #[error("invalid parameter")]
    Param,
}

pub type Result<T> = core::result::Result<T, CryptoError>;
