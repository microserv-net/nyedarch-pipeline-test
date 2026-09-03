//! Runtime-side: authenticate + decrypt + decompress + restore. Called only
//! after authorization has produced `payload_key` (spec §26/§36). Streams chunk
//! by chunk; bounded plaintext memory.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use nyedarch_crypto::compose;

use crate::format::Parsed;
use crate::manifest::{Kind, Manifest};
use crate::pipeline::{open_chunk_codec, TAG_MANIFEST, TAG_PAYLOAD};

pub struct RestoreReport {
    pub files: usize,
    pub dirs: usize,
    pub symlinks: usize,
    pub bytes: u64,
}

struct Sink {
    path: PathBuf,
    remaining: u64,
    handle: Option<fs::File>,
    mode: u32,
    mtime: i64,
}

impl Sink {
    fn write(&mut self, data: &[u8]) -> Result<(), ()> {
        if self.handle.is_none() {
            self.handle = Some(fs::File::create(&self.path).map_err(|_| ())?);
        }
        self.handle.as_mut().unwrap().write_all(data).map_err(|_| ())
    }
    fn finalize(&mut self) -> Result<(), ()> {
        if self.handle.is_none() {
            self.handle = Some(fs::File::create(&self.path).map_err(|_| ())?);
        }
        if let Some(h) = self.handle.as_mut() {
            h.flush().map_err(|_| ())?;
        }
        self.handle = None;
        apply_meta(&self.path, self.mode, self.mtime);
        Ok(())
    }
}

#[cfg(unix)]
fn apply_meta(path: &Path, mode: u32, mtime: i64) {
    use std::os::unix::fs::PermissionsExt;
    if mode != 0 {
        // Mask to permission bits.
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o7777));
    }
    let _ = mtime; // best-effort; precise mtime needs libc utimensat (later).
}
#[cfg(not(unix))]
fn apply_meta(_path: &Path, _mode: u32, _mtime: i64) {}

fn make_symlink(target: &str, link: &Path) -> Result<(), ()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link).map_err(|_| ())
    }
    #[cfg(not(unix))]
    {
        let _ = (target, link);
        Ok(())
    }
}

/// Open only the manifest (runtime learns structure after auth).
pub fn open_manifest(parsed: &Parsed, payload_key: &[u8; 32]) -> Result<Manifest, ()> {
    let flags = parsed.header.policy.to_flags();
    let context = compose::payload_aad(&parsed.header.binding(), flags);
    let raw = open_chunk_codec(parsed.header.compression, payload_key, &context, TAG_MANIFEST, 0, true, &parsed.sealed_manifest)?;
    let m: Manifest = bincode::deserialize(&raw).map_err(|_| ())?;
    if !m.validate() {
        return Err(());
    }
    Ok(m)
}

/// Restore the whole package to `out_root`.
pub fn restore(parsed: &Parsed, payload_key: &[u8; 32], out_root: &Path) -> Result<RestoreReport, ()> {
    let manifest = open_manifest(parsed, payload_key)?;
    let flags = parsed.header.policy.to_flags();
    let context = compose::payload_aad(&parsed.header.binding(), flags);

    fs::create_dir_all(out_root).map_err(|_| ())?;

    let mut dirs = 0usize;
    for e in &manifest.entries {
        if e.kind == Kind::Dir {
            fs::create_dir_all(out_root.join(&e.path)).map_err(|_| ())?;
            dirs += 1;
        }
    }

    let mut sinks: Vec<Sink> = Vec::new();
    for e in &manifest.entries {
        if e.kind == Kind::File {
            let path = out_root.join(&e.path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|_| ())?;
            }
            sinks.push(Sink { path, remaining: e.size, handle: None, mode: e.mode, mtime: e.mtime });
        }
    }

    let mut si = 0usize;
    let mut total_bytes = 0u64;
    let n = parsed.chunks.len();
    for (i, chunk) in parsed.chunks.iter().enumerate() {
        let is_last = i + 1 == n;
        let raw = open_chunk_codec(parsed.header.compression, payload_key, &context, TAG_PAYLOAD, i as u32, is_last, chunk)?;
        let mut data: &[u8] = &raw;
        while !data.is_empty() {
            while si < sinks.len() && sinks[si].remaining == 0 {
                sinks[si].finalize()?;
                si += 1;
            }
            if si >= sinks.len() {
                break;
            }
            let take = std::cmp::min(sinks[si].remaining as usize, data.len());
            sinks[si].write(&data[..take])?;
            sinks[si].remaining -= take as u64;
            total_bytes += take as u64;
            data = &data[take..];
            if sinks[si].remaining == 0 {
                sinks[si].finalize()?;
                si += 1;
            }
        }
    }
    while si < sinks.len() {
        sinks[si].finalize()?;
        si += 1;
    }

    let mut symlinks = 0usize;
    for e in &manifest.entries {
        if e.kind == Kind::Symlink {
            if let Some(t) = &e.link_target {
                make_symlink(t, &out_root.join(&e.path))?;
                symlinks += 1;
            }
        }
    }

    let files = manifest.entries.iter().filter(|e| e.kind == Kind::File).count();
    Ok(RestoreReport { files, dirs, symlinks, bytes: total_bytes })
}
