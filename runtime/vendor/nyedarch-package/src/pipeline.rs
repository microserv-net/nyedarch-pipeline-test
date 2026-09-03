//! Chunk compression + authenticated sealing. Bounded plaintext memory: only
//! one chunk (default 1 MiB) of plaintext exists at a time (spec §15).

use zeroize::Zeroizing;

use nyedarch_crypto::aead::{open, seal, Sealed};

/// Per-chunk AAD binds the header context, a section tag, the chunk index, and
/// the terminal flag — so reorder/truncation/section-confusion fails auth.
pub fn chunk_aad(context: &[u8], tag: &[u8], index: u32, is_last: bool) -> Vec<u8> {
    let mut a = Vec::with_capacity(context.len() + tag.len() + 5);
    a.extend_from_slice(context);
    a.extend_from_slice(tag);
    a.extend_from_slice(&index.to_le_bytes());
    a.push(is_last as u8);
    a
}

use crate::format::{COMPRESSION_DEFLATE, COMPRESSION_ZSTD};

/// Compress with the algorithm selected for this package.
pub fn compress_block_with(codec: u8, raw: &[u8]) -> Vec<u8> {
    match codec {
        COMPRESSION_ZSTD => {
            // Prefix the exact uncompressed length so decompression allocates
            // precisely once. Without this the decoder must guess an upper
            // bound, which either over-allocates badly or risks unbounded
            // allocation from attacker-influenced data.
            let body = zstd::bulk::compress(raw, 6).unwrap_or_default();
            let mut out = Vec::with_capacity(4 + body.len());
            out.extend_from_slice(&(raw.len() as u32).to_le_bytes());
            out.extend_from_slice(&body);
            out
        }
        _ => miniz_oxide::deflate::compress_to_vec(raw, 6),
    }
}

/// Decompress using the algorithm recorded in the package header.
pub fn decompress_block_with(codec: u8, comp: &[u8]) -> Result<Vec<u8>, ()> {
    match codec {
        COMPRESSION_ZSTD => {
            // Exact-size allocation from the recorded length, still bounded so
            // a forged length cannot force a huge allocation. The AEAD tag is
            // verified before we get here, so this length is authenticated.
            const MAX: usize = 256 * 1024 * 1024;
            if comp.len() < 4 {
                return Err(());
            }
            let len = u32::from_le_bytes([comp[0], comp[1], comp[2], comp[3]]) as usize;
            if len > MAX {
                return Err(());
            }
            let out = zstd::bulk::decompress(&comp[4..], len).map_err(|_| ())?;
            if out.len() != len {
                return Err(()); // recorded length must match reality
            }
            Ok(out)
        }
        COMPRESSION_DEFLATE => miniz_oxide::inflate::decompress_to_vec(comp).map_err(|_| ()),
        _ => Err(()), // unknown codec: fail closed
    }
}

pub fn compress_block(raw: &[u8]) -> Vec<u8> {
    compress_block_with(COMPRESSION_DEFLATE, raw)
}
pub fn decompress_block(comp: &[u8]) -> Result<Vec<u8>, ()> {
    decompress_block_with(COMPRESSION_DEFLATE, comp)
}

pub fn seal_chunk_codec(
    codec: u8,
    key: &[u8; 32],
    context: &[u8],
    tag: &[u8],
    index: u32,
    is_last: bool,
    plaintext: &[u8],
) -> Result<Vec<u8>, ()> {
    let comp = compress_block_with(codec, plaintext);
    let aad = chunk_aad(context, tag, index, is_last);
    let sealed = seal(key, &aad, &comp).map_err(|_| ())?;
    Ok(sealed.to_bytes())
}

pub fn open_chunk_codec(
    codec: u8,
    key: &[u8; 32],
    context: &[u8],
    tag: &[u8],
    index: u32,
    is_last: bool,
    bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ()> {
    let sealed = Sealed::from_bytes(bytes).map_err(|_| ())?;
    let aad = chunk_aad(context, tag, index, is_last);
    let comp = open(key, &aad, &sealed).map_err(|_| ())?;
    let raw = decompress_block_with(codec, &comp).map_err(|_| ())?;
    Ok(Zeroizing::new(raw))
}

/// Back-compat wrappers defaulting to DEFLATE.
pub fn seal_chunk(key: &[u8; 32], context: &[u8], tag: &[u8], index: u32, is_last: bool, pt: &[u8]) -> Result<Vec<u8>, ()> {
    seal_chunk_codec(COMPRESSION_DEFLATE, key, context, tag, index, is_last, pt)
}
pub fn open_chunk(key: &[u8; 32], context: &[u8], tag: &[u8], index: u32, is_last: bool, b: &[u8]) -> Result<Zeroizing<Vec<u8>>, ()> {
    open_chunk_codec(COMPRESSION_DEFLATE, key, context, tag, index, is_last, b)
}

pub const TAG_MANIFEST: &[u8] = b"manifest";
pub const TAG_PAYLOAD: &[u8] = b"payload";
