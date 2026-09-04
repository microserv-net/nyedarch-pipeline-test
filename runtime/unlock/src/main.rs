//! Opens the encrypted capsule source inside the build runner.
//!
//! This program contains no secret. The key arrives in NYEDARCH_SOURCE_KEY,
//! which the workflow populates from a repository secret, so it exists only in
//! the runner's memory for the length of the build.
//!
//! Failure is always fatal: a build must never continue with a partially
//! written or unauthenticated source tree.

use std::io::Read;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

const MAGIC: &[u8; 10] = b"NYARCHIVE2";
const AAD: &[u8] = b"nyedarch:v1:source-archive";

fn die(msg: &str) -> ! {
    eprintln!("nyedarch-unlock: {msg}");
    std::process::exit(1);
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 { return None; }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2], 16).ok()).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        die("usage: nyedarch-unlock <archive> <output-directory>");
    }
    let key_hex = std::env::var("NYEDARCH_SOURCE_KEY")
        .unwrap_or_else(|_| die("NYEDARCH_SOURCE_KEY is not set; the repository secret is missing"));
    let key = unhex(&key_hex).unwrap_or_else(|| die("NYEDARCH_SOURCE_KEY is not valid hex"));
    if key.len() != 32 {
        die("NYEDARCH_SOURCE_KEY must be 32 bytes");
    }

    let mut blob = Vec::new();
    std::fs::File::open(&args[1])
        .unwrap_or_else(|e| die(&format!("cannot open the archive: {e}")))
        .read_to_end(&mut blob)
        .unwrap_or_else(|e| die(&format!("cannot read the archive: {e}")));

    if blob.len() < 24 {
        die("the archive is truncated");
    }
    let (nonce, ct) = blob.split_at(24);

    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .unwrap_or_else(|_| die("invalid key"));
    // Authenticated: a modified archive fails here rather than producing a
    // subtly wrong source tree.
    let plain = cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: AAD })
        .unwrap_or_else(|_| die("the archive failed authentication: wrong key or modified content"));

    if plain.len() < MAGIC.len() || &plain[..MAGIC.len()] != MAGIC {
        die("unrecognised archive format");
    }

    let out_root = PathBuf::from(&args[2]);
    let mut i = MAGIC.len();
    let mut count = 0usize;
    while i < plain.len() {
        if i + 4 > plain.len() { die("truncated entry header"); }
        let nlen = u32::from_le_bytes(plain[i..i+4].try_into().unwrap()) as usize;
        i += 4;
        if i + nlen > plain.len() { die("truncated entry name"); }
        let name = String::from_utf8_lossy(&plain[i..i+nlen]).to_string();
        i += nlen;
        if i >= plain.len() { die("truncated entry flags"); }
        let flags = plain[i];
        i += 1;
        if i + 8 > plain.len() { die("truncated entry length"); }
        let dlen = u64::from_le_bytes(plain[i..i+8].try_into().unwrap()) as usize;
        i += 8;
        if i + dlen > plain.len() { die("truncated entry data"); }
        let data = &plain[i..i+dlen];
        i += dlen;

        // Refuse anything that would escape the output directory.
        if name.starts_with('/') || name.split('/').any(|c| c == ".." || c.is_empty()) {
            die(&format!("refusing unsafe path in archive: {name}"));
        }
        let dest = out_root.join(&name);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .unwrap_or_else(|e| die(&format!("cannot create {}: {e}", parent.display())));
        }
        std::fs::write(&dest, data)
            .unwrap_or_else(|e| die(&format!("cannot write {}: {e}", dest.display())));
        // Restore the executable bit. Without this an unpacked script cannot
        // run, which is how this was found.
        #[cfg(unix)]
        if flags & 1 != 0 {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755));
        }
        #[cfg(not(unix))]
        let _ = flags;
        count += 1;
    }
    println!("nyedarch-unlock: restored {count} file(s) into {}", out_root.display());
    let _ = Path::new(&args[1]);
}
