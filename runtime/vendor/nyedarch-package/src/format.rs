//! On-disk NYEDArch package format (spec §58/§59). All secret-bearing sections are
//! sealed with `nyedarch-crypto`; framing (lengths, counts) is plaintext and leaks
//! no content. The header context is bound as AEAD associated data so tampering
//! with binding/policy fails authentication.

use serde::{Deserialize, Serialize};

use nyedarch_core::{Policy, Ulid, PACKAGE_FORMAT_VERSION, PACKAGE_MAGIC};

/// Serializable Argon2id parameters mirrored for the header.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Argon2ParamsSer {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}
impl From<Argon2ParamsSer> for nyedarch_crypto::Argon2Params {
    fn from(p: Argon2ParamsSer) -> Self {
        nyedarch_crypto::Argon2Params { m_cost: p.m_cost, t_cost: p.t_cost, p_cost: p.p_cost }
    }
}
impl From<nyedarch_crypto::Argon2Params> for Argon2ParamsSer {
    fn from(p: nyedarch_crypto::Argon2Params) -> Self {
        Argon2ParamsSer { m_cost: p.m_cost, t_cost: p.t_cost, p_cost: p.p_cost }
    }
}

/// Compression identifier. Versioned so a capsule always decompresses with the
/// algorithm it was sealed with (spec §59).
pub const COMPRESSION_DEFLATE: u8 = 1;
/// zstd — the default for new packages: better ratio and throughput.
pub const COMPRESSION_ZSTD: u8 = 2;

/// Plaintext, versioned header. Carries no secrets.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Header {
    pub crypto_version: u16,
    pub package_id: [u8; 16],
    pub runtime_binding: [u8; 32],
    pub policy: Policy,
    pub argon: Argon2ParamsSer,
    pub package_salt: [u8; 32],
    pub compression: u8,
    pub chunk_size: u32,
}

impl Header {
    pub fn binding(&self) -> nyedarch_crypto::Binding {
        nyedarch_crypto::Binding {
            package_id: self.package_id,
            runtime_binding: self.runtime_binding,
            crypto_version: self.crypto_version,
        }
    }
    pub fn package_ulid(&self) -> Ulid {
        Ulid(self.package_id)
    }
}

/// Parsed package: framing resolved, sections still sealed.
pub struct Parsed {
    pub header: Header,
    pub sealed_policy: Vec<u8>,   // sealed fingerprint-authorization record
    pub sealed_manifest: Vec<u8>, // sealed manifest chunk
    pub chunks: Vec<Vec<u8>>,     // sealed payload chunks, in order
}

fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}
fn get_u32(b: &[u8], off: &mut usize) -> Option<u32> {
    let e = off.checked_add(4)?;
    if e > b.len() {
        return None;
    }
    let v = u32::from_le_bytes(b[*off..e].try_into().ok()?);
    *off = e;
    Some(v)
}
fn get_slice<'a>(b: &'a [u8], off: &mut usize, len: usize) -> Option<&'a [u8]> {
    let e = off.checked_add(len)?;
    if e > b.len() {
        return None;
    }
    let s = &b[*off..e];
    *off = e;
    Some(s)
}

pub fn write_package(
    header: &Header,
    sealed_policy: &[u8],
    sealed_manifest: &[u8],
    chunks: &[Vec<u8>],
) -> Result<Vec<u8>, ()> {
    let header_bytes = bincode::serialize(header).map_err(|_| ())?;
    let mut out = Vec::new();
    out.extend_from_slice(&PACKAGE_MAGIC);
    out.extend_from_slice(&PACKAGE_FORMAT_VERSION.to_le_bytes());
    put_u32(&mut out, header_bytes.len() as u32);
    out.extend_from_slice(&header_bytes);
    put_u32(&mut out, sealed_policy.len() as u32);
    out.extend_from_slice(sealed_policy);
    put_u32(&mut out, sealed_manifest.len() as u32);
    out.extend_from_slice(sealed_manifest);
    put_u32(&mut out, chunks.len() as u32);
    for c in chunks {
        put_u32(&mut out, c.len() as u32);
        out.extend_from_slice(c);
    }
    Ok(out)
}

pub fn parse(b: &[u8]) -> Result<Parsed, ()> {
    let mut off = 0usize;
    let magic = get_slice(b, &mut off, 6).ok_or(())?;
    if magic != PACKAGE_MAGIC {
        return Err(());
    }
    let ver = u16::from_le_bytes(get_slice(b, &mut off, 2).ok_or(())?.try_into().map_err(|_| ())?);
    if ver != PACKAGE_FORMAT_VERSION {
        return Err(());
    }
    let hlen = get_u32(b, &mut off).ok_or(())? as usize;
    let hbytes = get_slice(b, &mut off, hlen).ok_or(())?;
    let header: Header = bincode::deserialize(hbytes).map_err(|_| ())?;
    let plen = get_u32(b, &mut off).ok_or(())? as usize;
    let sealed_policy = get_slice(b, &mut off, plen).ok_or(())?.to_vec();
    let mlen = get_u32(b, &mut off).ok_or(())? as usize;
    let sealed_manifest = get_slice(b, &mut off, mlen).ok_or(())?.to_vec();
    let ccount = get_u32(b, &mut off).ok_or(())? as usize;
    let mut chunks = Vec::with_capacity(ccount);
    for _ in 0..ccount {
        let clen = get_u32(b, &mut off).ok_or(())? as usize;
        chunks.push(get_slice(b, &mut off, clen).ok_or(())?.to_vec());
    }
    Ok(Parsed { header, sealed_policy, sealed_manifest, chunks })
}
