//! Capsule launching (drag-and-drop execution).
//!
//! The client can start a finished `.nyarch` capsule as a **fully independent
//! process**. This is a convenience for the operator, and it is important to be
//! precise about what it does and does not mean:
//!
//! - The launched capsule performs its OWN authorization. The client grants it
//!   nothing, passes it no key material, and cannot make it open. Launching a
//!   capsule on an unauthorized machine fails exactly as double-clicking it
//!   would.
//! - The capsule is spawned detached, with its own stdio, so the client is not
//!   in its trust path and cannot observe its passphrase entry.
//!
//! On Windows this is also the reliable way to run a `.nyarch` file, because
//! `CreateProcess` dispatches on file content while the shell's `PATHEXT`
//! resolution does not recognise the extension.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Debug)]
pub enum LaunchError {
    NotFound,
    NotACapsule,
    PermissionSetFailed,
    SpawnFailed(String),
}

impl std::fmt::Display for LaunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LaunchError::NotFound => write!(f, "file not found"),
            LaunchError::NotACapsule => {
                write!(f, "not a NYEDArch capsule (expected a .{} file)", crate::CAPSULE_EXTENSION)
            }
            LaunchError::PermissionSetFailed => write!(f, "could not set executable permission"),
            LaunchError::SpawnFailed(e) => write!(f, "could not start the capsule: {e}"),
        }
    }
}

/// Validate a dropped path before offering to run it.
pub fn validate(path: &Path) -> Result<(), LaunchError> {
    if !path.is_file() {
        return Err(LaunchError::NotFound);
    }
    if !crate::is_capsule_path(path) {
        return Err(LaunchError::NotACapsule);
    }
    Ok(())
}

/// Launch a capsule as an independent process.
///
/// `out_dir` is passed as the capsule's extraction target. Returns the child's
/// process id. The child is NOT waited on: it owns its own lifetime, its own
/// terminal interaction, and its own authorization outcome.
pub fn launch(path: &Path, out_dir: Option<&Path>) -> Result<u32, LaunchError> {
    validate(path)?;

    // A capsule downloaded from a build artifact often arrives without the
    // executable bit (zip archives do not always preserve it). Restore it
    // rather than failing with a confusing "permission denied".
    crate::make_executable(path).map_err(|_| LaunchError::PermissionSetFailed)?;

    // Use an absolute path: a bare relative name is not resolved as a program.
    let program: PathBuf = path.canonicalize().map_err(|_| LaunchError::NotFound)?;

    let mut cmd = Command::new(&program);
    if let Some(o) = out_dir {
        cmd.arg(o);
    }
    if let Some(parent) = program.parent() {
        cmd.current_dir(parent);
    }
    // Inherit stdio so the capsule can prompt for its passphrase itself. The
    // client never brokers that secret.
    cmd.stdin(Stdio::inherit()).stdout(Stdio::inherit()).stderr(Stdio::inherit());

    match cmd.spawn() {
        Ok(child) => Ok(child.id()),
        Err(e) => Err(LaunchError::SpawnFailed(e.to_string())),
    }
}

/// Guidance shown when a capsule cannot be run from a terminal on Windows.
pub fn terminal_hint() -> &'static str {
    if cfg!(windows) {
        "On Windows, `capsule.nyarch` typed into cmd or PowerShell will not run, \
         because the shell resolves executables via PATHEXT. Launch it from the \
         NYEDArch client, or add .NYARCH to PATHEXT."
    } else {
        "Run it from any terminal: ./capsule.nyarch [output-directory]"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let mut d = std::env::temp_dir();
        d.push(format!("nyarch-launch-{}-{}", std::process::id(), name));
        d
    }

    #[test]
    fn rejects_non_capsule_files() {
        let p = tmp("notacapsule.txt");
        std::fs::write(&p, b"hello").unwrap();
        assert!(matches!(validate(&p), Err(LaunchError::NotACapsule)));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn rejects_missing_files() {
        assert!(matches!(validate(Path::new("/nonexistent/x.nyarch")), Err(LaunchError::NotFound)));
    }

    #[test]
    fn accepts_capsule_extension() {
        let p = tmp("good.nyarch");
        std::fs::write(&p, b"stub").unwrap();
        assert!(validate(&p).is_ok());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    #[cfg(unix)]
    fn launch_restores_executable_bit_and_spawns() {
        use std::os::unix::fs::PermissionsExt;
        let p = tmp("run.nyarch");
        // A trivial real executable so the spawn genuinely succeeds.
        std::fs::write(&p, b"#!/bin/sh\nexit 0\n").unwrap();
        // Arrive WITHOUT the executable bit, as a zip extraction would.
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let pid = launch(&p, None).expect("capsule should launch");
        assert!(pid > 0);
        let mode = std::fs::metadata(&p).unwrap().permissions().mode();
        assert_eq!(mode & 0o111, 0o111);
        let _ = std::fs::remove_file(&p);
    }
}
