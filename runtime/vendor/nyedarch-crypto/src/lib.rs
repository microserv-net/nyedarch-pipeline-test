//! # nyedarch-crypto
//!
//! Security-critical cryptographic core for NYEDArch. This crate deliberately
//! contains *no* GUI, GitHub, filesystem, or platform code (spec §29 builder/
//! runtime separation, §70 clean crate boundaries). It exposes:
//!
//! - `kdf`      — Argon2id passphrase KDF + HKDF-SHA512 expansion.
//! - `aead`     — XChaCha20-Poly1305 authenticated encryption with AAD binding.
//! - `geo`      — deterministic location quantization + accuracy rejection.
//! - `timewin`  — time-window policy factor with a replaceable time source.
//! - `compose`  — final key composition: the invariant that authorization
//!                materially participates in key derivation (spec §32 / exec §7).
//!
//! The central guarantee this crate is designed around:
//!
//! > The payload key cannot be produced unless every enabled authorization
//! > factor contributed correct high-entropy input. Bypassing a conditional
//! > branch does not yield the key.
//!
//! Anti-tamper / anti-RE (spec §30-§32) live in the *runtime* crate and are
//! defense-in-depth around this boundary — they are not this boundary.

#![forbid(unsafe_code)]

#[macro_use]
mod bitflags_lite;

pub mod aead;
pub mod compose;
pub mod error;
pub mod geo;
pub mod kdf;
pub mod rng;
pub mod timewin;
pub mod version;

pub use compose::{Binding, Contributions, PolicyFlags};
pub use error::{CryptoError, Result};
pub use kdf::Argon2Params;

use zeroize::Zeroizing;

/// Seal the fingerprint-authorization record (and any other protected policy)
/// under a per-build **bootstrap key** (spec §11/§17).
///
/// The bootstrap key does NOT come from the fingerprint — that would be the
/// forbidden circular dependency. It is a per-build diversified secret held by
/// the runtime template's protected-fragment machinery (a later crate). This
/// function is the crypto seam: the record stays ciphertext-at-rest inside the
/// runtime and is only opened after integrity checks, then the *matched*
/// fingerprint selects its 32-byte factor secret which feeds `compose`.
pub mod policy_seal {
    use super::*;
    use crate::aead::{open, seal_with, Sealed};
    use crate::kdf::hkdf_key;
    use crate::rng::RandomSource;
    use crate::version::LABEL_POLICY_SEAL;

    /// Derive the record-sealing subkey.
    ///
    /// Correction pass §4: the subkey is bound to BOTH the per-build bootstrap
    /// key AND the runtime's own identity commitment. The runtime supplies its
    /// *embedded* commitment constant — never the value read from the package
    /// header — so a header/payload swap fails to unseal cryptographically,
    /// not merely because a comparison returned false.
    ///
    /// Consequence for transplantation (Runtime A + Package B):
    ///   subkey_A = KDF(bootstrap_A, commitment_A)  ≠  subkey_B
    /// so the protected fingerprint-authorization record of package B cannot be
    /// opened by runtime A, no factor secret is selected, and no payload key can
    /// be composed. See KEY_HIERARCHY.md §4.
    fn subkey(
        bootstrap_key: &[u8; 32],
        runtime_commitment: &[u8; 32],
        salt: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>> {
        let mut ikm = Zeroizing::new(Vec::with_capacity(64));
        ikm.extend_from_slice(bootstrap_key);
        ikm.extend_from_slice(runtime_commitment);
        hkdf_key(salt, &ikm, LABEL_POLICY_SEAL)
    }

    pub fn seal_record_with<R: RandomSource + ?Sized>(
        rng: &R,
        bootstrap_key: &[u8; 32],
        runtime_commitment: &[u8; 32],
        salt: &[u8],
        aad: &[u8],
        record: &[u8],
    ) -> Result<Sealed> {
        let k = subkey(bootstrap_key, runtime_commitment, salt)?;
        seal_with(rng, &*k, aad, record)
    }

    #[cfg(feature = "os-rng")]
    pub fn seal_record(
        bootstrap_key: &[u8; 32],
        runtime_commitment: &[u8; 32],
        salt: &[u8],
        aad: &[u8],
        record: &[u8],
    ) -> Result<Sealed> {
        seal_record_with(&crate::rng::OsRandom, bootstrap_key, runtime_commitment, salt, aad, record)
    }

    /// Open the protected record. `runtime_commitment` MUST be the runtime's own
    /// embedded constant (correction pass §4).
    pub fn open_record(
        bootstrap_key: &[u8; 32],
        runtime_commitment: &[u8; 32],
        salt: &[u8],
        aad: &[u8],
        sealed: &Sealed,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let k = subkey(bootstrap_key, runtime_commitment, salt)?;
        open(&*k, aad, sealed)
    }
}

/// High-level capsule: seal/open the payload with the composed key.
pub struct Capsule;

impl Capsule {
    /// Builder side: derive the payload key from the (build-time known)
    /// contributions and seal the payload.
    pub fn seal_with<R: rng::RandomSource + ?Sized>(
        rng: &R,
        payload: &[u8],
        package_salt: &[u8],
        binding: &Binding,
        flags: PolicyFlags,
        contrib: &Contributions,
    ) -> Result<aead::Sealed> {
        let key = compose::derive_payload_key(package_salt, binding, flags, contrib)?;
        let aad = compose::payload_aad(binding, flags);
        aead::seal_with(rng, &*key, &aad, payload)
    }

    #[cfg(feature = "os-rng")]
    pub fn seal(
        payload: &[u8],
        package_salt: &[u8],
        binding: &Binding,
        flags: PolicyFlags,
        contrib: &Contributions,
    ) -> Result<aead::Sealed> {
        Self::seal_with(&rng::OsRandom, payload, package_salt, binding, flags, contrib)
    }

    /// Runtime side: re-derive the key from the *runtime-collected*
    /// contributions and open the payload. Wrong factor => wrong key => auth
    /// failure (spec §36 no plaintext before authorization).
    pub fn open(
        sealed: &aead::Sealed,
        package_salt: &[u8],
        binding: &Binding,
        flags: PolicyFlags,
        contrib: &Contributions,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let key = compose::derive_payload_key(package_salt, binding, flags, contrib)?;
        let aad = compose::payload_aad(binding, flags);
        aead::open(&*key, &aad, sealed)
    }
}

/// Convenience: derive the passphrase contribution for `Contributions`.
pub fn passphrase_key(
    passphrase: &[u8],
    salt: &[u8],
    params: Argon2Params,
) -> Result<Zeroizing<[u8; 32]>> {
    kdf::passphrase_contribution(passphrase, salt, params)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_roundtrip_and_aad_tamper() {
        let key = [1u8; 32];
        let s = aead::seal_with(&rng::FixedSource(7), &key, b"aad", b"hello").unwrap();
        assert_eq!(aead::open(&key, b"aad", &s).unwrap().as_slice(), b"hello");
        // Wrong AAD fails authentication.
        assert!(aead::open(&key, b"nope", &s).is_err());
    }

    #[test]
    fn policy_seal_bootstrap_roundtrip() {
        let boot = [3u8; 32];
        let salt = [4u8; 32];
        let commit = [5u8; 32];
        let s = policy_seal::seal_record_with(&rng::FixedSource(1), &boot, &commit, &salt, b"hdr", b"fingerprint-record").unwrap();
        let out = policy_seal::open_record(&boot, &commit, &salt, b"hdr", &s).unwrap();
        assert_eq!(out.as_slice(), b"fingerprint-record");
        // A different bootstrap key (attacker guess) cannot open it.
        assert!(policy_seal::open_record(&[0u8; 32], &commit, &salt, b"hdr", &s).is_err());
        // Correction pass §4: a DIFFERENT RUNTIME (same package) cannot open the
        // record even with the right bootstrap key — transplantation fails
        // cryptographically, not by a patchable comparison.
        assert!(policy_seal::open_record(&boot, &[9u8; 32], &salt, b"hdr", &s).is_err());
    }

    #[test]
    fn geo_rejects_poor_accuracy() {
        let r = geo::Reading { lat_deg: 12.97, lon_deg: 77.59, accuracy_m: 2000.0 };
        assert!(geo::quantize(&r, geo::ToleranceMeters(100)).is_err());
        let ok = geo::Reading { lat_deg: 12.97, lon_deg: 77.59, accuracy_m: 30.0 };
        assert!(geo::quantize(&ok, geo::ToleranceMeters(100)).is_ok());
    }

    #[test]
    fn time_window_inside_and_outside() {
        let sched = timewin::DailySchedule {
            slots_minutes: vec![14 * 60],
            tolerance_minutes: 15,
            tz_offset_minutes: 330, // IST
        };
        // Construct a UTC instant that is 14:05 IST -> inside ±15.
        // 14:05 IST = 08:35 UTC. Pick 2024-01-01 08:35:00 UTC.
        let inside = 1_704_098_100; // 2024-01-01T08:35:00Z
        assert!(sched.window_id(inside).is_ok());
        let outside = inside + 40 * 60; // +40 min -> outside window
        assert!(sched.window_id(outside).is_err());
        // Every accepted time in the window derives the SAME id.
        let a = sched.window_id(inside).unwrap();
        let b = sched.window_id(inside + 5 * 60).unwrap();
        assert_eq!(a, b);

        // Day-invariance: a recurring daily schedule must derive the same key
        // tomorrow, next week, and next year — otherwise a "daily" policy would
        // silently become single-day.
        let tomorrow = sched.window_id(inside + 86_400).unwrap();
        let next_year = sched.window_id(inside + 365 * 86_400).unwrap();
        assert_eq!(a, tomorrow);
        assert_eq!(a, next_year);

        // The builder can commit to the same canonical window without a clock.
        assert_eq!(a, sched.window_id_for_slot(14 * 60).unwrap());
        assert!(sched.window_id_for_slot(9 * 60).is_err());
    }
}
