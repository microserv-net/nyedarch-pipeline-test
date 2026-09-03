//! Platform-adaptive signal collection (spec §7/§16). Each OS exposes different
//! trustworthy identifiers; this module returns whatever is *actually*
//! available on the running machine, tagged with a strength. It never fabricates
//! a signal and never substitutes a weak signal for a strong one silently
//! (spec §9) — absence is simply absence, recorded by the caller.
//!
//! Only the Linux path executes in the current build/test sandbox. The Windows
//! and macOS paths are real, cfg-gated code that runs on those systems.

use super::Strength;

pub fn name() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "linux"
    }
    #[cfg(target_os = "macos")]
    {
        "macos"
    }
    #[cfg(target_os = "windows")]
    {
        "windows"
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        "other"
    }
}

/// Returns `(signal_name, strength, raw_value_bytes)` for available signals.
pub fn collect() -> Vec<(String, Strength, Vec<u8>)> {
    #[cfg(target_os = "linux")]
    {
        linux()
    }
    #[cfg(target_os = "macos")]
    {
        macos()
    }
    #[cfg(target_os = "windows")]
    {
        windows()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Vec::new()
    }
}

#[allow(dead_code)]
fn push_file(out: &mut Vec<(String, Strength, Vec<u8>)>, name: &str, path: &str, s: Strength) {
    if let Ok(v) = std::fs::read(path) {
        let trimmed: Vec<u8> = v.iter().copied().filter(|b| !b" \n\r\t\0".contains(b)).collect();
        if !trimmed.is_empty() {
            out.push((name.to_string(), s, trimmed));
        }
    }
}

#[cfg(target_os = "linux")]
fn linux() -> Vec<(String, Strength, Vec<u8>)> {
    let mut out = Vec::new();
    // Firmware/hardware-backed (often root-only; absent when unreadable).
    push_file(&mut out, "dmi.product_uuid", "/sys/class/dmi/id/product_uuid", Strength::Strong);
    push_file(&mut out, "dmi.board_serial", "/sys/class/dmi/id/board_serial", Strength::Strong);
    push_file(&mut out, "dmi.product_serial", "/sys/class/dmi/id/product_serial", Strength::Strong);
    // TPM presence contributes a Strong marker (identity binding is a later,
    // hardware-attested enhancement — recorded here as availability).
    if std::path::Path::new("/sys/class/tpm/tpm0").exists() {
        out.push(("tpm.present".into(), Strength::Strong, b"tpm0".to_vec()));
    }
    // OS install identity.
    push_file(&mut out, "machine-id", "/etc/machine-id", Strength::Medium);
    if !out.iter().any(|(n, _, _)| n == "machine-id") {
        push_file(&mut out, "machine-id", "/var/lib/dbus/machine-id", Strength::Medium);
    }
    // Weak but always-present anchors.
    if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
        if let Some(line) = cpuinfo.lines().find(|l| l.starts_with("model name")) {
            if let Some((_, v)) = line.split_once(':') {
                out.push(("cpu.model".into(), Strength::Weak, v.trim().as_bytes().to_vec()));
            }
        }
    }
    push_file(&mut out, "hostname", "/etc/hostname", Strength::Weak);
    out
}

#[cfg(target_os = "macos")]
fn macos() -> Vec<(String, Strength, Vec<u8>)> {
    // Real code, runs on macOS. IOPlatformUUID is Secure-Enclave-era stable
    // hardware identity; Enclave-attested binding is a later enhancement.
    use std::process::Command;
    let mut out = Vec::new();
    if let Ok(o) = Command::new("/usr/sbin/ioreg").args(["-rd1", "-c", "IOPlatformExpertDevice"]).output() {
        let s = String::from_utf8_lossy(&o.stdout);
        if let Some(line) = s.lines().find(|l| l.contains("IOPlatformUUID")) {
            if let Some(v) = line.split('"').nth(3) {
                out.push(("io.platform_uuid".into(), Strength::Strong, v.as_bytes().to_vec()));
            }
        }
    }
    if let Ok(o) = Command::new("/usr/sbin/sysctl").args(["-n", "machdep.cpu.brand_string"]).output() {
        let v = String::from_utf8_lossy(&o.stdout);
        let v = v.trim();
        if !v.is_empty() {
            out.push(("cpu.brand".into(), Strength::Weak, v.as_bytes().to_vec()));
        }
    }
    out
}

#[cfg(target_os = "windows")]
fn windows() -> Vec<(String, Strength, Vec<u8>)> {
    // Real code, runs on Windows. MachineGuid is the OS install identity; the
    // production build additionally binds TPM via the platform crate.
    use std::process::Command;
    let mut out = Vec::new();
    if let Ok(o) = Command::new("reg")
        .args(["query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"])
        .output()
    {
        let s = String::from_utf8_lossy(&o.stdout);
        if let Some(line) = s.lines().find(|l| l.contains("MachineGuid")) {
            if let Some(v) = line.split_whitespace().last() {
                out.push(("crypto.machine_guid".into(), Strength::Medium, v.as_bytes().to_vec()));
            }
        }
    }
    if let Ok(o) = Command::new("wmic").args(["csproduct", "get", "UUID"]).output() {
        let s = String::from_utf8_lossy(&o.stdout);
        if let Some(v) = s.lines().nth(1).map(|l| l.trim().to_string()) {
            if !v.is_empty() {
                out.push(("csproduct.uuid".into(), Strength::Strong, v.into_bytes()));
            }
        }
    }
    out
}
