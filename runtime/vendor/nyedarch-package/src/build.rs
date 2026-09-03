//! Builder-side: walk inputs into a manifest and seal a package. Reads the
//! filesystem; never writes plaintext payload anywhere (spec §36).

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use nyedarch_crypto::compose;

use crate::format::{write_package, Header};
use crate::manifest::{Entry, Kind, Manifest};
use crate::pipeline::{seal_chunk_codec, TAG_MANIFEST, TAG_PAYLOAD};

/// A file to include, with its on-disk source and archive-relative path.
pub struct FileSrc {
    pub rel: String,
    pub src: PathBuf,
    pub size: u64,
}

fn rel_path(base: &Path, p: &Path) -> String {
    p.strip_prefix(base)
        .unwrap_or(p)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Recursively collect a manifest + file source list from input paths.
pub fn collect(inputs: &[PathBuf]) -> std::io::Result<(Manifest, Vec<FileSrc>)> {
    let mut entries = Vec::new();
    let mut files = Vec::new();
    for input in inputs {
        let base = input.parent().unwrap_or(Path::new(""));
        walk(base, input, &mut entries, &mut files)?;
    }
    Ok((Manifest { version: Manifest::VERSION, entries }, files))
}

fn meta_bits(md: &fs::Metadata) -> (u32, i64) {
    #[cfg(unix)]
    {
        (md.mode(), md.mtime())
    }
    #[cfg(not(unix))]
    {
        let _ = md;
        (0, 0)
    }
}

fn walk(
    base: &Path,
    p: &Path,
    entries: &mut Vec<Entry>,
    files: &mut Vec<FileSrc>,
) -> std::io::Result<()> {
    let md = fs::symlink_metadata(p)?;
    let (mode, mtime) = meta_bits(&md);
    let rel = rel_path(base, p);
    if md.file_type().is_symlink() {
        let target = fs::read_link(p)?.to_string_lossy().replace('\\', "/");
        entries.push(Entry { path: rel, kind: Kind::Symlink, mode, mtime, size: 0, link_target: Some(target) });
    } else if md.is_dir() {
        entries.push(Entry { path: rel, kind: Kind::Dir, mode, mtime, size: 0, link_target: None });
        let mut children: Vec<_> = fs::read_dir(p)?.filter_map(|e| e.ok()).map(|e| e.path()).collect();
        children.sort();
        for c in children {
            walk(base, &c, entries, files)?;
        }
    } else {
        let size = md.len();
        entries.push(Entry { path: rel.clone(), kind: Kind::File, mode, mtime, size, link_target: None });
        files.push(FileSrc { rel, src: p.to_path_buf(), size });
    }
    Ok(())
}

/// Seal a complete package.
///
/// `payload_key` was already derived by the caller from the build-time
/// authorization factors (`compose::derive_payload_key`). `sealed_policy` is the
/// bootstrap-sealed fingerprint-authorization record produced elsewhere.
pub fn seal_package(
    header: &Header,
    sealed_policy: &[u8],
    payload_key: &[u8; 32],
    manifest: &Manifest,
    files: &[FileSrc],
) -> Result<Vec<u8>, ()> {
    let flags = header.policy.to_flags();
    let context = compose::payload_aad(&header.binding(), flags);

    // Manifest -> its own sealed chunk.
    let manifest_bytes = bincode::serialize(manifest).map_err(|_| ())?;
    let sealed_manifest = seal_chunk_codec(header.compression, payload_key, &context, TAG_MANIFEST, 0, true, &manifest_bytes)?;

    // Payload: stream files into fixed-size chunks. Bounded plaintext memory.
    let chunk_size = header.chunk_size as usize;
    let total: u64 = files.iter().map(|f| f.size).sum();
    let mut sealed_chunks: Vec<Vec<u8>> = Vec::new();
    let mut buf: Vec<u8> = Vec::with_capacity(chunk_size);
    let mut produced: u64 = 0;
    let mut index: u32 = 0;

    let mut file_iter = files.iter();
    let mut cur = file_iter.next().map(|f| (fs::File::open(&f.src), f.size, 0u64));

    'outer: loop {
        // Fill buf up to chunk_size.
        while buf.len() < chunk_size {
            match cur.as_mut() {
                None => break,
                Some((fh_res, size, done)) => {
                    let fh = match fh_res {
                        Ok(fh) => fh,
                        Err(_) => return Err(()),
                    };
                    if *done >= *size {
                        cur = file_iter.next().map(|f| (fs::File::open(&f.src), f.size, 0u64));
                        continue;
                    }
                    let want = std::cmp::min(chunk_size - buf.len(), (*size - *done) as usize);
                    let start = buf.len();
                    buf.resize(start + want, 0);
                    let n = fh.read(&mut buf[start..]).map_err(|_| ())?;
                    buf.truncate(start + n);
                    *done += n as u64;
                    if n == 0 {
                        // Short read; advance to next file.
                        cur = file_iter.next().map(|f| (fs::File::open(&f.src), f.size, 0u64));
                    }
                }
            }
        }
        if buf.is_empty() && cur.is_none() {
            break 'outer;
        }
        produced += buf.len() as u64;
        let is_last = produced >= total;
        sealed_chunks.push(seal_chunk_codec(header.compression, payload_key, &context, TAG_PAYLOAD, index, is_last, &buf)?);
        index += 1;
        buf.clear();
        if is_last {
            break 'outer;
        }
    }

    write_package(header, sealed_policy, &sealed_manifest, &sealed_chunks)
}
