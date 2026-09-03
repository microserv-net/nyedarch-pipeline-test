//! Final key composition — the security core (spec §25, §32, and execution
//! instruction §7).
//!
//! THE INVARIANT: the payload key is derived from the *contributions of every
//! enabled factor* as HKDF input keying material. If any required factor is
//! wrong or absent, the IKM is wrong, so the derived key is wrong, so the
//! AEAD open fails. There is no boolean `authorized` that gates access to a
//! key that exists independently — patching a branch to `true` cannot
//! synthesize the missing 32-byte contributions.
//!
//! Composition also binds package identity, runtime identity, crypto version
//! and policy into the derivation `info` and the payload AAD, so a payload
//! cannot be transplanted into a different runtime (spec §27).

use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::kdf::hkdf_key;
use crate::version::*;

crate::bitflags_lite! {
    pub struct PolicyFlags: u8 {
        const MACHINE    = 0b0000_0001; // always set
        const PASSPHRASE = 0b0000_0010; // always set
        const LOCATION   = 0b0000_0100;
        const TIME       = 0b0000_1000;
    }
}

/// Immutable cryptographic binding of a package to one generated runtime.
#[derive(Clone, Debug)]
pub struct Binding {
    pub package_id: [u8; 16],       // ULID-derived bytes (spec §39)
    pub runtime_binding: [u8; 32],  // per-build runtime identity commitment
    pub crypto_version: u16,
}

/// The raw per-factor contributions gathered by the runtime after each factor
/// has actually succeeded. Presence MUST match the policy or composition fails
/// closed.
#[derive(Default)]
pub struct Contributions {
    /// 32-byte secret selected by the *matched* trusted fingerprint (spec §11
    /// bootstrap: the fingerprint selects a high-entropy secret; it is not the
    /// key itself, and a non-matching fingerprint selects nothing).
    pub machine_secret: Option<[u8; KEY_LEN]>,
    /// Argon2id output of the passphrase (already derived; see kdf.rs).
    pub passphrase_key: Option<Zeroizing<[u8; KEY_LEN]>>,
    /// Quantized location cell id (present iff LOCATION enabled).
    pub location_cell: Option<Vec<u8>>,
    /// Time window id (present iff TIME enabled).
    pub time_window: Option<Vec<u8>>,
}

fn domain(salt: &[u8], label: &[u8], raw: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    hkdf_key(salt, raw, label)
}

/// Serialize the binding+policy into the context string used both as HKDF
/// `info` and as payload AAD.
fn context(binding: &Binding, flags: PolicyFlags) -> Vec<u8> {
    let mut c = Vec::with_capacity(LABEL_PAYLOAD_KEY.len() + 2 + 1 + 16 + 32);
    c.extend_from_slice(LABEL_PAYLOAD_KEY);
    c.extend_from_slice(&binding.crypto_version.to_le_bytes());
    c.push(flags.bits());
    c.extend_from_slice(&binding.package_id);
    c.extend_from_slice(&binding.runtime_binding);
    c
}

/// Derive the payload key. `package_salt` is public, stored in the header.
///
/// Fails closed (spec §29) if any enabled factor's contribution is missing.
pub fn derive_payload_key(
    package_salt: &[u8],
    binding: &Binding,
    flags: PolicyFlags,
    contrib: &Contributions,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if binding.crypto_version != CRYPTO_VERSION {
        return Err(CryptoError::UnsupportedVersion(binding.crypto_version));
    }
    // Machine + passphrase are mandatory and cannot be disabled (spec §5/§14).
    if !flags.contains(PolicyFlags::MACHINE) || !flags.contains(PolicyFlags::PASSPHRASE) {
        return Err(CryptoError::Param);
    }

    // Assemble IKM from enabled factors, in fixed canonical order, each
    // domain-separated first so no two factors' bytes can be confused.
    let mut ikm: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(4 * KEY_LEN));

    let m = contrib.machine_secret.ok_or(CryptoError::Authorization)?;
    ikm.extend_from_slice(domain(package_salt, LABEL_MACHINE, &m)?.as_ref());

    let p = contrib.passphrase_key.as_ref().ok_or(CryptoError::Authorization)?;
    ikm.extend_from_slice(domain(package_salt, LABEL_PASSPHRASE, p.as_ref())?.as_ref());

    if flags.contains(PolicyFlags::LOCATION) {
        let cell = contrib.location_cell.as_ref().ok_or(CryptoError::Authorization)?;
        ikm.extend_from_slice(domain(package_salt, LABEL_LOCATION, cell)?.as_ref());
    } else if contrib.location_cell.is_some() {
        return Err(CryptoError::Param); // presence must match policy
    }

    if flags.contains(PolicyFlags::TIME) {
        let win = contrib.time_window.as_ref().ok_or(CryptoError::Authorization)?;
        ikm.extend_from_slice(domain(package_salt, LABEL_TIME, win)?.as_ref());
    } else if contrib.time_window.is_some() {
        return Err(CryptoError::Param);
    }

    let info = context(binding, flags);
    hkdf_key(package_salt, &ikm, &info)
}

/// The AAD bound into the payload AEAD — identical context as key `info`, so
/// tamper with binding/policy fails authentication.
pub fn payload_aad(binding: &Binding, flags: PolicyFlags) -> Vec<u8> {
    context(binding, flags)
}
