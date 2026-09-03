//! Runtime hardening: anti-tamper and anti-analysis (spec §30/§31).
//!
//! ## What this module is, and is not
//!
//! It is **not** the confidentiality boundary. The payload key is composed from
//! authorization factor contributions; an attacker who defeats every check here
//! still cannot derive it. This module exists to raise the cost of *reaching,
//! observing, and iterating on* that boundary.
//!
//! Every technique below is individually bypassable by a competent analyst with
//! sufficient time. That is stated deliberately, per spec §31/§79: the goal is
//! layered cost, not an impossibility claim.
//!
//! ## An honest split: what can bind cryptographically, and what cannot
//!
//! It is tempting to claim that anti-debug results are mixed into key
//! derivation, so that patching a check yields the wrong key. **That claim would
//! be false, and the design would be broken.** Key material must be exactly
//! reproducible on every legitimate run; debugger state, timing, and loaded
//! libraries are not reproducible. A key derived from them would deny honest
//! users on a loaded laptop and would have to be "corrected" by a fallback —
//! which is precisely the silent downgrade the specification forbids (§36).
//!
//! So this module separates two categories, and does not blur them:
//!
//! **(a) Deterministic commitments — may participate in cryptography.**
//! The embedded package bytes and the per-build diversifier are identical on
//! every run, so they can be, and are, bound into the derivation context and
//! AEAD associated data.
//!
//! **(b) Environment observations — defense-in-depth only.**
//! Debugger presence, timing anomalies, and injection markers are folded into a
//! tamper accumulator used for control-flow diversification and diagnostics.
//! They are deliberately **not** key material, and are **not** consumed as a
//! single `if detected { exit() }` gate either (§31), since one patched branch
//! would defeat that. They raise analysis cost. They do not, and are not
//! claimed to, prevent extraction by an attacker who defeats them.
//!
//! The real bypass-resistance lives in `nyedarch_crypto::compose`: no accumulator
//! value, patched or genuine, produces the payload key without the actual
//! authorization factors.

use core::sync::atomic::{AtomicU64, Ordering};

/// Per-build diversifier, baked in by the generator so two capsules never share
/// hardening state layout or constants.
#[derive(Clone, Copy)]
pub struct Diversifier(pub u64);

/// Accumulates environment observations. Redundant and independent, so that
/// neutralising one probe does not zero the whole accumulator (spec §30:
/// assume the attacker patches a single check).
pub struct TamperAccumulator {
    state: AtomicU64,
}

impl TamperAccumulator {
    pub fn new(d: Diversifier) -> Self {
        Self { state: AtomicU64::new(d.0 ^ 0x9E37_79B9_7F4A_7C15) }
    }

    /// Mix an observation. Non-commutative-ish mixing so ordering matters and a
    /// replayed partial sequence does not reproduce the value.
    fn mix(&self, tag: u64, observed: u64) {
        let mut s = self.state.load(Ordering::Relaxed);
        s ^= tag.rotate_left((observed & 63) as u32);
        s = s.wrapping_mul(0x9E37_79B9_7F4A_7C15).rotate_left(31);
        s ^= observed;
        self.state.store(s, Ordering::Relaxed);
    }

    /// Final accumulator value, mixed into key-derivation context.
    pub fn finish(&self) -> u64 {
        self.state.load(Ordering::Relaxed)
    }

    /// Run all environment probes. Each probe contributes regardless of its
    /// result — a "clean" observation is as much an input as a "dirty" one, so
    /// there is no branch that can be forced to the good path.
    pub fn observe_environment(&self) {
        self.mix(0xA1, probe_debugger() as u64);
        self.mix(0xB2, probe_ptrace_self() as u64);
        self.mix(0xC3, probe_timing_anomaly() as u64);
        self.mix(0xD4, probe_environment_markers() as u64);
    }
}

/// Debugger presence via the platform's own reporting.
///
/// Limitation: trivially defeated by patching `TracerPid` reads, by a debugger
/// that hides itself, or by running under emulation. Contributes an input, not
/// a verdict.
fn probe_debugger() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("TracerPid:") {
                    let pid: u64 = rest.trim().parse().unwrap_or(0);
                    return if pid == 0 { 0 } else { pid };
                }
            }
        }
        0
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Windows: IsDebuggerPresent / CheckRemoteDebuggerPresent.
        // macOS: sysctl KERN_PROC info P_TRACED flag.
        // Both are real platform calls that must be compiled on those systems;
        // no fabricated value is returned here.
        0
    }
}

/// Self-trace occupancy. On Linux a process may be traced only once, so a
/// successful self-attach implies no debugger currently holds the slot.
///
/// Limitation: this is intentionally NOT performed via `unsafe` ptrace here —
/// the crate forbids unsafe code, so we infer from the same status interface.
/// A dedicated build may implement the stronger variant behind an audited
/// unsafe block.
fn probe_ptrace_self() -> u64 {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/self/stat")
            .ok()
            .and_then(|s| s.split_whitespace().nth(2).map(|f| f.as_bytes()[0] as u64))
            .unwrap_or(0)
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

/// Coarse timing observation across a fixed workload. Single-stepping or heavy
/// instrumentation inflates this dramatically.
///
/// Limitation: noisy on loaded or virtualised hosts, which is exactly why it is
/// quantized coarsely and mixed rather than compared to a threshold — a false
/// positive must not deny a legitimate user outright.
fn probe_timing_anomaly() -> u64 {
    let start = std::time::Instant::now();
    let mut acc: u64 = 0x243F_6A88_85A3_08D3;
    for i in 0..2048u64 {
        acc = acc.wrapping_mul(6364136223846793005).wrapping_add(i);
    }
    let ns = start.elapsed().as_nanos() as u64;
    // Bucket to the nearest power-of-two magnitude: stable across normal
    // machines, wildly different under single-stepping.
    let magnitude = 64 - ns.leading_zeros() as u64;
    magnitude ^ (acc & 0xF)
}

/// Well-known analysis-environment markers.
///
/// Limitation: an attacker who knows this list simply removes the markers.
/// Contributes an input; never a standalone verdict.
fn probe_environment_markers() -> u64 {
    let mut n = 0u64;
    for var in ["LD_PRELOAD", "LD_AUDIT", "DYLD_INSERT_LIBRARIES"] {
        if std::env::var_os(var).is_some() {
            n += 1;
        }
    }
    n
}

/// Integrity commitment over the embedded package.
///
/// The runtime recomputes a digest of the package bytes it carries and mixes it
/// into the accumulator. Because the payload AEAD already binds the header
/// context, this is a *cheap early* consistency signal rather than the
/// authoritative check — the authoritative check is AEAD authentication, which
/// cannot be patched away without the key.
pub fn package_commitment(package: &[u8]) -> u64 {
    let mut h: u64 = 0xCBF2_9CE4_8422_2325;
    for b in package {
        h ^= *b as u64;
        h = h.wrapping_mul(0x1000_0000_01B3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accumulator_is_deterministic_per_build_in_a_stable_environment() {
        let a = TamperAccumulator::new(Diversifier(7));
        a.mix(1, 2);
        a.mix(3, 4);
        let b = TamperAccumulator::new(Diversifier(7));
        b.mix(1, 2);
        b.mix(3, 4);
        assert_eq!(a.finish(), b.finish());
    }

    #[test]
    fn ordering_matters() {
        let a = TamperAccumulator::new(Diversifier(7));
        a.mix(1, 2);
        a.mix(3, 4);
        let b = TamperAccumulator::new(Diversifier(7));
        b.mix(3, 4);
        b.mix(1, 2);
        assert_ne!(a.finish(), b.finish(), "replayed out-of-order probes must differ");
    }

    #[test]
    fn different_builds_diverge() {
        let a = TamperAccumulator::new(Diversifier(1));
        let b = TamperAccumulator::new(Diversifier(2));
        a.observe_environment();
        b.observe_environment();
        assert_ne!(a.finish(), b.finish(), "per-build diversification must hold");
    }

    #[test]
    fn package_commitment_detects_modification() {
        let p = b"sealed-package-bytes";
        let mut q = p.to_vec();
        q[3] ^= 0xff;
        assert_ne!(package_commitment(p), package_commitment(&q));
    }
}
