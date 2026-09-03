//! Versioned cryptographic format constants and domain-separation labels.
//!
//! Everything that participates in key derivation is versioned (spec §59) so
//! future formats can be rejected safely and cryptographic agility is possible.

/// Bumped on any breaking change to the key-composition or AEAD framing.
pub const CRYPTO_VERSION: u16 = 1;

/// AEAD in use for the payload. Recorded so the format can migrate later.
pub const AEAD_ID_XCHACHA20POLY1305: u8 = 1;

/// Passphrase KDF identifier.
pub const KDF_ID_ARGON2ID: u8 = 1;

// --- Domain-separation labels -------------------------------------------------
// Distinct, collision-resistant ASCII labels prevent cross-purpose reuse of the
// same derived bytes (spec §25 "do NOT simply concatenate strings and hash").

pub const LABEL_PASSPHRASE: &[u8] = b"nyedarch:v1:factor:passphrase";
pub const LABEL_MACHINE: &[u8] = b"nyedarch:v1:factor:machine";
pub const LABEL_LOCATION: &[u8] = b"nyedarch:v1:factor:location";
pub const LABEL_TIME: &[u8] = b"nyedarch:v1:factor:time";
pub const LABEL_PAYLOAD_KEY: &[u8] = b"nyedarch:v1:payload-key";
pub const LABEL_POLICY_SEAL: &[u8] = b"nyedarch:v1:policy-seal";

/// Length of every internal key / factor contribution.
pub const KEY_LEN: usize = 32;
/// XChaCha20-Poly1305 nonce length.
pub const XNONCE_LEN: usize = 24;
/// Minimum passphrase-KDF salt length.
pub const SALT_LEN: usize = 32;
