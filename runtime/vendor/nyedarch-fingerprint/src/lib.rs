//! nyedarch-fingerprint — adaptive, platform-appropriate machine fingerprinting
//! (spec §7-§12). Produces a deterministic fingerprint id from whatever
//! trustworthy, stable signals are actually available, records *what was
//! available and how strong it was* (spec §9), and never exposes raw hardware
//! identifiers (spec §10 — only salted digests are retained).

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

mod platform;

const DOMAIN: &[u8] = b"nyedarch:v1:fingerprint";

/// How trustworthy/stable a signal is considered.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Strength {
    /// CPU model, hostname — present everywhere but not machine-unique.
    Weak,
    /// OS install identity (e.g. machine-id) — stable, moderately unique.
    Medium,
    /// Firmware/hardware/TPM/Enclave-backed identity — strongest available.
    Strong,
}

/// Metadata about one captured signal. The raw value is NOT stored; only a
/// salted digest (equality-comparable, non-reversible for practical hardware
/// serials) plus its name and strength (spec §10).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignalMeta {
    pub name: String,
    pub strength: Strength,
    pub digest: [u8; 32],
}

/// A captured fingerprint: a deterministic id plus the availability inventory.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Fingerprint {
    pub id: [u8; 32],
    pub signals: Vec<SignalMeta>,
    /// Best strength that actually contributed to `id`.
    pub best_strength: Strength,
    pub platform: String,
}

fn digest(name: &str, raw: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(b"|sig|");
    h.update(name.as_bytes());
    h.update(b"|");
    h.update(raw);
    h.finalize().into()
}

/// Capture the current machine's fingerprint using platform-appropriate signals.
pub fn capture() -> Fingerprint {
    let raw_signals = platform::collect(); // Vec<(name, Strength, raw bytes)>
    let mut signals: Vec<SignalMeta> = raw_signals
        .iter()
        .map(|(name, strength, raw)| SignalMeta { name: name.clone(), strength: *strength, digest: digest(name, raw) })
        .collect();
    signals.sort_by(|a, b| a.name.cmp(&b.name));

    // The id is derived from Strong+Medium signals when available, else from
    // whatever exists (degrade, but record availability — spec §9).
    let best_strength = signals.iter().map(|s| s.strength).max().unwrap_or(Strength::Weak);
    let id_threshold = if signals.iter().any(|s| s.strength >= Strength::Medium) {
        Strength::Medium
    } else {
        Strength::Weak
    };

    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(b"|id|");
    for s in signals.iter().filter(|s| s.strength >= id_threshold) {
        h.update(s.name.as_bytes());
        h.update(b"=");
        h.update(s.digest);
        h.update(b";");
    }
    let id: [u8; 32] = h.finalize().into();

    Fingerprint { id, signals, best_strength, platform: platform::name().to_string() }
}

impl Fingerprint {
    /// Short hex id for display (spec §10: no raw identifiers, just an opaque id).
    pub fn id_hex(&self) -> String {
        self.id.iter().map(|b| format!("{:02x}", b)).collect()
    }
    pub fn matches(&self, other_id: &[u8; 32]) -> bool {
        use hmac::digest::consts::U32;
        let _ = std::marker::PhantomData::<U32>;
        // Constant-time compare.
        let mut diff = 0u8;
        for i in 0..32 {
            diff |= self.id[i] ^ other_id[i];
        }
        diff == 0
    }
}

// --- .nyfp authenticated portable record (spec §10) --------------------------

pub mod nyfp {
    use super::*;
    use hmac::{Hmac, Mac};
    use sha2::Sha512;

    type HmacSha512 = Hmac<Sha512>;
    const NYFP_VERSION: u16 = 1;
    const MAC_LEN: usize = 64;

    /// Portable fingerprint record. Labels/tags are metadata, NOT authorization
    /// secrets (spec §10) — but the whole record is MAC-authenticated so a user
    /// cannot edit `labels` (or the id) without detection.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct Record {
        pub version: u16,
        pub fingerprint: Fingerprint,
        pub labels: Vec<String>,
        pub created_unix: i64,
        pub app_version: String,
    }

    #[derive(Debug, thiserror::Error)]
    pub enum NyfpError {
        #[error("serialization")]
        Serde,
        #[error("authentication failed (record tampered or wrong key)")]
        Auth,
        #[error("unsupported version")]
        Version,
    }

    fn mac(key: &[u8], body: &[u8]) -> [u8; MAC_LEN] {
        let mut m = <HmacSha512 as Mac>::new_from_slice(key).expect("hmac key");
        m.update(&NYFP_VERSION.to_le_bytes());
        m.update(body);
        let out = m.finalize().into_bytes();
        let mut t = [0u8; MAC_LEN];
        t.copy_from_slice(&out);
        t
    }

    /// Authenticate arbitrary bytes in the same container. Used for the EULA
    /// acceptance record (spec §13) so it cannot be forged or back-dated.
    pub fn seal_bytes(key: &[u8], body: &[u8]) -> Result<Vec<u8>, NyfpError> {
        let tag = mac(key, body);
        let mut out = Vec::with_capacity(2 + 4 + body.len() + MAC_LEN);
        out.extend_from_slice(&NYFP_VERSION.to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// Verify and return the authenticated body.
    pub fn open_bytes(key: &[u8], bytes: &[u8]) -> Result<Vec<u8>, NyfpError> {
        if bytes.len() < 6 + MAC_LEN {
            return Err(NyfpError::Auth);
        }
        let ver = u16::from_le_bytes([bytes[0], bytes[1]]);
        if ver != NYFP_VERSION {
            return Err(NyfpError::Version);
        }
        let blen = u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as usize;
        let body_end = 6 + blen;
        if bytes.len() != body_end + MAC_LEN {
            return Err(NyfpError::Auth);
        }
        let body = &bytes[6..body_end];
        let mut m = <HmacSha512 as Mac>::new_from_slice(key).map_err(|_| NyfpError::Auth)?;
        m.update(&NYFP_VERSION.to_le_bytes());
        m.update(body);
        m.verify_slice(&bytes[body_end..]).map_err(|_| NyfpError::Auth)?;
        Ok(body.to_vec())
    }

    /// Serialize + authenticate a record with the client's fingerprint-signing
    /// key. Layout: [u16 version][u32 body_len][body][64-byte MAC].
    pub fn seal(key: &[u8], record: &Record) -> Result<Vec<u8>, NyfpError> {
        let body = bincode::serialize(record).map_err(|_| NyfpError::Serde)?;
        let tag = mac(key, &body);
        let mut out = Vec::with_capacity(2 + 4 + body.len() + MAC_LEN);
        out.extend_from_slice(&NYFP_VERSION.to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&body);
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// Verify + deserialize. Constant-time MAC check (spec §10 authenticated).
    pub fn open(key: &[u8], bytes: &[u8]) -> Result<Record, NyfpError> {
        if bytes.len() < 6 + MAC_LEN {
            return Err(NyfpError::Auth);
        }
        let ver = u16::from_le_bytes([bytes[0], bytes[1]]);
        if ver != NYFP_VERSION {
            return Err(NyfpError::Version);
        }
        let blen = u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as usize;
        let body_start = 6;
        let body_end = body_start + blen;
        if bytes.len() != body_end + MAC_LEN {
            return Err(NyfpError::Auth);
        }
        let body = &bytes[body_start..body_end];
        let tag = &bytes[body_end..];
        let mut m = <HmacSha512 as Mac>::new_from_slice(key).map_err(|_| NyfpError::Auth)?;
        m.update(&NYFP_VERSION.to_le_bytes());
        m.update(body);
        m.verify_slice(tag).map_err(|_| NyfpError::Auth)?;
        bincode::deserialize(body).map_err(|_| NyfpError::Serde)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_is_deterministic() {
        let a = capture();
        let b = capture();
        assert_eq!(a.id, b.id, "same machine state must reproduce the same id");
        assert!(!a.signals.is_empty(), "at least one signal should be available");
    }

    #[test]
    fn nyfp_roundtrip_and_tamper() {
        let key = [9u8; 32];
        let rec = nyfp::Record {
            version: 1,
            fingerprint: capture(),
            labels: vec!["HR".into(), "Bangalore".into()],
            created_unix: 1_700_000_000,
            app_version: "0.0.1".into(),
        };
        let sealed = nyfp::seal(&key, &rec).unwrap();
        let back = nyfp::open(&key, &sealed).unwrap();
        assert_eq!(back, rec);

        // Flip a byte in the labels region -> authentication fails.
        let mut bad = sealed.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 0xff;
        assert!(nyfp::open(&key, &bad).is_err());

        // Wrong key -> authentication fails.
        assert!(nyfp::open(&[0u8; 32], &sealed).is_err());
    }
}
