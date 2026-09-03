//! Versioned manifest (spec §14): preserves relative paths, directory
//! hierarchy, unix mode bits, mtimes, sizes, and symlink targets.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    Symlink,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    /// Relative path with '/' separators, no leading slash, no `..`.
    pub path: String,
    pub kind: Kind,
    /// Unix mode bits (0 on platforms without them).
    pub mode: u32,
    /// Modification time (seconds since epoch), best-effort.
    pub mtime: i64,
    /// File content length in bytes (0 for dirs/symlinks).
    pub size: u64,
    /// Symlink target (relative), if `kind == Symlink`.
    pub link_target: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Manifest {
    pub version: u16,
    pub entries: Vec<Entry>,
}

impl Manifest {
    pub const VERSION: u16 = 1;

    /// Reject path traversal / absolute paths (defense against a malicious
    /// package writing outside the extraction root).
    pub fn validate(&self) -> bool {
        self.entries.iter().all(|e| {
            !e.path.starts_with('/')
                && !e.path.split('/').any(|c| c == ".." || c == "")
                && e.path.chars().next().map(|c| c != '\\').unwrap_or(false)
        }) || self.entries.is_empty()
    }
}
