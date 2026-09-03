//! nyedarch-core — shared identifiers, versioned headers, and error taxonomy used
//! by both the builder and (a minimized subset of) the runtime.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

pub mod ids;
pub mod launch;
pub use ids::Ulid;

/// Format magic for on-disk NYEDArch packages: "NYEDArch\x01".
pub const PACKAGE_MAGIC: [u8; 6] = *b"NYARCH";
pub const PACKAGE_FORMAT_VERSION: u16 = 1;

/// Errors shared across builder-side crates. The *runtime* uses its own
/// minimized, non-oracle error surface (spec §51).
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("crypto: {0}")]
    Crypto(#[from] nyedarch_crypto::CryptoError),
    #[error("serialization")]
    Serde,
    #[error("bad magic or unsupported package version")]
    Format,
    #[error("io")]
    Io,
}

pub type Result<T> = core::result::Result<T, CoreError>;

/// Policy flags mirror the crypto layer but are serializable for the header.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Policy {
    pub location: bool,
    pub time: bool,
    /// Execution behaviour (spec §37).
    pub one_shot: bool,
}

impl Policy {
    /// Convert to the crypto layer's flags (machine + passphrase always on).
    pub fn to_flags(self) -> nyedarch_crypto::PolicyFlags {
        let mut f = nyedarch_crypto::PolicyFlags::MACHINE | nyedarch_crypto::PolicyFlags::PASSPHRASE;
        if self.location {
            f = f | nyedarch_crypto::PolicyFlags::LOCATION;
        }
        if self.time {
            f = f | nyedarch_crypto::PolicyFlags::TIME;
        }
        f
    }
}

/// The protected fingerprint-authorization record (spec §11/§17). Maps each
/// trusted fingerprint id to a fresh high-entropy 32-byte factor secret. This
/// is sealed with the runtime's bootstrap key (NOT any fingerprint) and stored
/// inside the package; the matched fingerprint *selects* its secret, which then
/// feeds the machine factor of key composition. No fingerprint is ever the key.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct PolicyRecord {
    pub entries: Vec<PolicyEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyEntry {
    /// The trusted fingerprint id (opaque, non-reversible).
    pub fingerprint_id: [u8; 32],
    /// The high-entropy secret selected when this fingerprint matches.
    pub factor_secret: [u8; 32],
    /// Human-facing labels/tags (metadata only, not authorization secrets).
    pub labels: Vec<String>,
}

impl PolicyRecord {
    /// Constant-time-ish lookup of the factor secret for a captured id.
    pub fn select(&self, current_id: &[u8; 32]) -> Option<[u8; 32]> {
        let mut found: Option<[u8; 32]> = None;
        for e in &self.entries {
            let mut diff = 0u8;
            for i in 0..32 {
                diff |= e.fingerprint_id[i] ^ current_id[i];
            }
            if diff == 0 {
                found = Some(e.factor_secret);
            }
        }
        found
    }
}

// --- NYEDArch capsule identity ---------------------------------------------

/// The NYEDArch capsule file extension, identical on every operating system.
///
/// A single cross-platform extension is a deliberate product decision: a capsule
/// is one artifact concept, so it carries one name everywhere rather than
/// `.exe` on Windows and nothing on Unix.
///
/// **Execution semantics, stated honestly:**
///
/// - **Linux / macOS**: the kernel dispatches on file content, not on the name.
///   With the executable bit set, `./capsule.nyarch` runs from any terminal.
/// - **Windows**: the shell resolves executability from the extension via
///   `PATHEXT`, so `capsule.nyarch` typed into cmd/PowerShell will NOT run
///   unmodified. `CreateProcess` itself does not care about the extension, so
///   the NYEDArch client launches it correctly, and adding `.NYARCH` to
///   `PATHEXT` enables terminal use.
///
/// Double-click is not expected to work anywhere without an OS-level file
/// association. This trade-off is documented rather than worked around by
/// silently emitting platform-specific extensions.
pub const CAPSULE_EXTENSION: &str = "nyarch";

/// Canonical capsule filename for a build id and target triple.
pub fn capsule_filename(build_id: &str, target: &str) -> String {
    format!("nyedarch-{build_id}-{target}.{CAPSULE_EXTENSION}")
}

/// Does this path look like a NYEDArch capsule?
pub fn is_capsule_path(path: &std::path::Path) -> bool {
    path.extension().and_then(|e| e.to_str()).map(|e| e.eq_ignore_ascii_case(CAPSULE_EXTENSION)).unwrap_or(false)
}

/// Grant executable permission, best effort.
///
/// On Unix this sets the owner/group/other execute bits. On Windows there is no
/// execute bit — executability is governed by extension and by the file not
/// being blocked by the "mark of the web", so this clears nothing and reports
/// success; the caller must not infer that a Windows terminal will run it.
pub fn make_executable(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let md = std::fs::metadata(path)?;
        let mut perms = md.permissions();
        let mode = perms.mode();
        perms.set_mode(mode | 0o111);
        std::fs::set_permissions(path, perms)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        // No-op by design; see the note above.
        let _ = std::fs::metadata(path)?;
        Ok(())
    }
}

#[cfg(test)]
mod capsule_tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn extension_is_stable_and_recognized() {
        assert_eq!(CAPSULE_EXTENSION, "nyarch");
        let n = capsule_filename("01HZY0", "x86_64-unknown-linux-gnu");
        assert!(n.ends_with(".nyarch"));
        assert!(is_capsule_path(Path::new(&n)));
        // Case-insensitive, because Windows and macOS filesystems are.
        assert!(is_capsule_path(Path::new("Thing.NYARCH")));
        assert!(!is_capsule_path(Path::new("thing.exe")));
        assert!(!is_capsule_path(Path::new("thing")));
    }

    #[test]
    #[cfg(unix)]
    fn make_executable_sets_exec_bits() {
        use std::os::unix::fs::PermissionsExt;
        let mut p = std::env::temp_dir();
        p.push(format!("nyarch-perm-{}", std::process::id()));
        std::fs::write(&p, b"x").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        make_executable(&p).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode();
        assert_eq!(mode & 0o111, 0o111, "executable bits must be set");
        let _ = std::fs::remove_file(&p);
    }
}
