//! Minimal ULID (spec §39: unique build/package identifiers). 48-bit ms
//! timestamp + 80-bit randomness, Crockford base32. Self-contained (no dep).

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ulid(pub [u8; 16]);

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

impl Ulid {
    pub fn new() -> Self {
        let ms: u128 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let mut b = [0u8; 16];
        let t = (ms as u64) & 0xFFFF_FFFF_FFFF; // 48 bits
        b[0] = (t >> 40) as u8;
        b[1] = (t >> 32) as u8;
        b[2] = (t >> 24) as u8;
        b[3] = (t >> 16) as u8;
        b[4] = (t >> 8) as u8;
        b[5] = t as u8;
        let mut r = [0u8; 10];
        let _ = getrandom::getrandom(&mut r);
        b[6..16].copy_from_slice(&r);
        Ulid(b)
    }

    pub fn to_string(&self) -> String {
        // 128 bits -> 26 Crockford base32 chars.
        let mut out = [0u8; 26];
        let mut val: u128 = 0;
        for &byte in &self.0 {
            val = (val << 8) | byte as u128;
        }
        for i in (0..26).rev() {
            out[i] = CROCKFORD[(val & 0x1f) as usize];
            val >>= 5;
        }
        String::from_utf8_lossy(&out).into_owned()
    }
}

impl Default for Ulid {
    fn default() -> Self {
        Self::new()
    }
}
