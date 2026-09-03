//! nyedarch-runtime — the library the *generated* capsule executable is built
//! around. It contains ONLY the runtime/decryption side (spec §29): no builder
//! capabilities. It runs the authorization state machine, and only on full
//! success derives the payload key and restores files.
//!
//! Central guarantee (spec §32 / exec §7): the payload key is produced by
//! `nyedarch_crypto::compose` from the *contributions of every enabled factor*.
//! A failed factor yields no contribution, so no key — there is no branch to
//! patch that hands over an already-formed key.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

pub mod harden;
pub mod location;
pub use location::SystemLocation;

use zeroize::Zeroizing;

use nyedarch_core::PolicyRecord;
use nyedarch_crypto::timewin::TimeSource;
use nyedarch_crypto::{compose, geo, passphrase_key, timewin, Argon2Params, Binding, Contributions, PolicyFlags};
use nyedarch_package::{format::parse, restore};

/// Explicit runtime states (spec §73). Kept for diagnostics/creator mode; the
/// normal path collapses all failures to a single generic outcome (spec §51).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Initializing,
    IntegrityCheck,
    /// Correction pass §5: the runtime asserts the package it carries is the
    /// one it was generated for, before any protected material is touched.
    BindingValidation,
    BootstrapPolicy,
    FingerprintAcquisition,
    FingerprintAuthorization,
    PassphraseAcquisition,
    LocationAcquisition,
    TimeAcquisition,
    KeyDerivation,
    /// Correction pass §5: composition of factor contributions into the payload
    /// key. Distinct from "the factors validated" — this is where cryptographic
    /// material is actually produced.
    PayloadKeyUnwrap,
    PayloadAuthentication,
    Decryption,
    Decompression,
    Extraction,
    /// Correction pass §5: extraction is verified before one-shot destruction
    /// is ever considered (never destroy on an unverified extraction).
    ExtractionVerification,
    Cleanup,
    Success,
    FailClosed,
}

/// Provider seams so the runtime *acquires* factors itself — never a manual
/// coordinate/time entry (spec §19/§22/§33). Headless/unavailable => fail closed.
pub trait PassphraseProvider {
    fn passphrase(&self) -> Option<Zeroizing<Vec<u8>>>;
}
pub trait LocationProvider {
    fn reading(&self) -> Option<geo::Reading>;
}
pub trait TimeProvider {
    fn now_unix(&self) -> Option<i64>;
}

/// Local clock time provider (prototype). FUTURE — LICENSE SERVER: authenticated time.
pub struct LocalTime;
impl TimeProvider for LocalTime {
    fn now_unix(&self) -> Option<i64> {
        Some(timewin::LocalClock.now_unix())
    }
}

/// Everything the generated binary embeds/needs to run.
pub struct Capsule<'a> {
    /// The full package bytes (embedded via include_bytes! in the generated bin).
    pub package: &'a [u8],
    /// Per-build bootstrap key (embedded; unseals only the fingerprint MAP,
    /// never the payload — see CRYPTO_FORMAT.md).
    pub bootstrap_key: [u8; 32],
    /// This runtime's OWN identity commitment, baked in at generation time
    /// (correction pass §4). It is deliberately NOT read from the package
    /// header: it is the value the runtime asserts *about itself*, and it is
    /// mixed into the policy-seal subkey so a transplanted package fails to
    /// unseal cryptographically rather than by a patchable comparison.
    pub runtime_commitment: [u8; 32],
    /// Optional time schedule (present iff policy.time).
    pub schedule: Option<timewin::DailySchedule>,
    /// Location tolerance (present iff policy.location).
    pub location_tolerance_m: Option<u32>,
    /// Where to extract on success.
    pub out_dir: PathBuf,
}

/// Result surfaced to the caller. In normal mode the generated binary prints a
/// single generic line for any failure (no oracle).
pub enum Outcome {
    Success { files: usize, dirs: usize, bytes: u64, out_dir: PathBuf },
    Failed,
}

/// Run the full authorization + extraction state machine. Fail-closed on every
/// error (spec §29/§60). Returns `Failed` generically; detailed state is only
/// exposed via the optional `trace` callback (creator/diagnostic mode).
pub fn run(
    cap: &Capsule<'_>,
    pass: &dyn PassphraseProvider,
    loc: Option<&dyn LocationProvider>,
    time: &dyn TimeProvider,
    mut trace: Option<&mut dyn FnMut(State)>,
) -> Outcome {
    macro_rules! step {
        ($s:expr) => {
            if let Some(t) = trace.as_deref_mut() {
                t($s);
            }
        };
    }
    macro_rules! fail {
        () => {{
            step!(State::FailClosed);
            // Best-effort cleanup of partial output (spec §35).
            let _ = std::fs::remove_dir_all(&cap.out_dir);
            return Outcome::Failed;
        }};
    }

    step!(State::Initializing);

    // INTEGRITY_CHECK. Layered (spec §30), and deliberately not reliant on any
    // one of these layers:
    //   1. deterministic commitment over the embedded package (cheap, early);
    //   2. environment observation, folded into the tamper accumulator for
    //      control-flow diversification — NOT key material, NOT a gate (§31);
    //   3. the authoritative check: AEAD authentication during decryption,
    //      which cannot be patched away because it needs the composed key.
    step!(State::IntegrityCheck);
    let acc = harden::TamperAccumulator::new(harden::Diversifier(
        harden::package_commitment(cap.package),
    ));
    acc.observe_environment();
    // Consumed as diversification input; never as an authorization verdict.
    let _diversified = acc.finish();
    let parsed = match parse(cap.package) {
        Ok(p) => p,
        Err(_) => fail!(),
    };
    let header = &parsed.header;
    let binding: Binding = header.binding();
    let flags: PolicyFlags = header.policy.to_flags();

    // ---------------------------------------------------------------------
    // CONSTANT-SHAPE AUTHORIZATION
    //
    // Every protection is evaluated, and key derivation always runs, before any
    // verdict is returned. A protection that fails does not return early: it
    // contributes a decoy value of the right shape, so the run continues and
    // fails at authenticated decryption like every other denial.
    //
    // Why: an earlier design returned as soon as a protection failed, so denial
    // latency revealed how far execution reached - a binding failure returned in
    // about 2 ms while a passphrase failure took about 100 ms, because only the
    // latter paid the Argon2id cost. That ~50x gap told an attacker whether they
    // had cleared the machine protection, which is exactly what the generic
    // failure message exists to hide.
    //
    // The cost is that every denial now pays the memory-hard passphrase cost.
    // That is the intended trade: the work is what makes the oracle disappear.
    //
    // A decoy never becomes a bypass. Each is random or arbitrary, so the
    // composed key is wrong and AEAD authentication fails. The decoys exist to
    // equalise timing, not to satisfy anything.
    // ---------------------------------------------------------------------

    // Diagnostic only; never used for control flow (see below).
    let mut authorized = true;

    // BINDING_VALIDATION.
    step!(State::BindingValidation);
    {
        let mut diff = 0u8;
        for i in 0..32 {
            diff |= header.runtime_binding[i] ^ cap.runtime_commitment[i];
        }
        if diff != 0 {
            authorized = false; // Runtime A + Package B
        }
    }

    // BOOTSTRAP_POLICY. On failure a decoy record is substituted so the
    // fingerprint stage still runs and still costs the same.
    step!(State::BootstrapPolicy);
    let ctx = compose::payload_aad(&binding, flags);
    let record: PolicyRecord = {
        use nyedarch_crypto::aead::Sealed;
        let opened = Sealed::from_bytes(&parsed.sealed_policy)
            .ok()
            .and_then(|sealed| {
                nyedarch_crypto::policy_seal::open_record(
                    &cap.bootstrap_key,
                    &cap.runtime_commitment, // OWN commitment, never the header's (§4)
                    &header.package_salt,
                    &ctx,
                    &sealed,
                )
                .ok()
            })
            .and_then(|bytes| bincode_decode::<PolicyRecord>(&bytes));
        match opened {
            Some(r) => r,
            None => {
                authorized = false;
                PolicyRecord::default()
            }
        }
    };

    // FINGERPRINT_ACQUISITION + AUTHORIZATION (spec §6 OR-set).
    step!(State::FingerprintAcquisition);
    let live = nyedarch_fingerprint::capture();
    step!(State::FingerprintAuthorization);
    let machine_secret = match record.select(&live.id) {
        Some(s) => s,
        None => {
            authorized = false;
            decoy32() // wrong key material, not a bypass
        }
    };

    // PASSPHRASE_ACQUISITION. Always derived, even when everything above has
    // already failed: this is the expensive stage and skipping it is precisely
    // what produced the timing oracle.
    step!(State::PassphraseAcquisition);
    let phrase = match pass.passphrase() {
        Some(p) => p,
        None => {
            authorized = false;
            Zeroizing::new(decoy32().to_vec())
        }
    };
    let argon: Argon2Params = header.argon.into();
    let pass_key = match passphrase_key(&phrase, &header.package_salt, argon) {
        Ok(k) => k,
        Err(_) => {
            authorized = false;
            Zeroizing::new(decoy32())
        }
    };

    // LOCATION_ACQUISITION (optional; auto-acquired, accuracy-checked).
    let mut location_cell: Option<Vec<u8>> = None;
    if header.policy.location {
        step!(State::LocationAcquisition);
        let cell = cap
            .location_tolerance_m
            .map(geo::ToleranceMeters)
            .and_then(|tol| loc.and_then(|l| l.reading()).map(|r| (r, tol)))
            .and_then(|(reading, tol)| geo::quantize(&reading, tol).ok());
        match cell {
            Some(c) => location_cell = Some(c),
            None => {
                // Provider missing, accuracy too poor, or wrong region.
                authorized = false;
                location_cell = Some(decoy32().to_vec());
            }
        }
    }

    // TIME_ACQUISITION (optional; runtime computes the window itself).
    let mut time_window: Option<Vec<u8>> = None;
    if header.policy.time {
        step!(State::TimeAcquisition);
        let w = time
            .now_unix()
            .and_then(|now| cap.schedule.as_ref().map(|s| (s, now)))
            .and_then(|(sched, now)| sched.window_id(now).ok());
        match w {
            Some(w) => time_window = Some(w),
            None => {
                authorized = false;
                time_window = Some(decoy32().to_vec());
            }
        }
    }

    // KEY_DERIVATION -> PAYLOAD_KEY_UNWRAP.
    step!(State::KeyDerivation);
    let contrib = Contributions {
        machine_secret: Some(machine_secret),
        passphrase_key: Some(pass_key),
        location_cell,
        time_window,
    };
    step!(State::PayloadKeyUnwrap);
    let payload_key = match compose::derive_payload_key(&header.package_salt, &binding, flags, &contrib) {
        Ok(k) => k,
        Err(_) => {
            authorized = false;
            Zeroizing::new(decoy32())
        }
    };

    // There is deliberately no `if !authorized { fail }` here.
    //
    // An earlier version short-circuited on the flag, which still leaked: a
    // binding or machine failure stopped at PayloadAuthentication while a wrong
    // passphrase ran on to authenticated decryption, so the depth reached still
    // distinguished them. Every run now takes the same path and every denial
    // fails in the same place, for the same reason: the composed key is wrong
    // and AEAD authentication rejects it.
    //
    // This is the design stated plainly - the cryptography is the boundary, and
    // there is no branch left to patch. `authorized` is retained only as a
    // diagnostic signal for creator mode; nothing in the control flow reads it.
    let _ = authorized;

    // PAYLOAD_AUTHENTICATION + DECRYPTION + DECOMPRESSION + EXTRACTION.
    step!(State::PayloadAuthentication);
    step!(State::Decryption);
    step!(State::Decompression);
    step!(State::Extraction);
    let report = match restore(&parsed, &payload_key, &cap.out_dir) {
        Ok(r) => r,
        Err(_) => fail!(),
    };

    // EXTRACTION_VERIFICATION (§5): confirm the restore actually produced the
    // manifest's content before any destructive one-shot step is permitted.
    step!(State::ExtractionVerification);
    if report.files == 0 && report.dirs == 0 && report.bytes == 0 {
        fail!();
    }

    // CLEANUP (keys zeroized on drop via Zeroizing). One-shot handled by caller.
    step!(State::Cleanup);
    step!(State::Success);
    Outcome::Success { files: report.files, dirs: report.dirs, bytes: report.bytes, out_dir: cap.out_dir.clone() }
}

/// A random 32-byte value used where a protection failed, so the run continues
/// with material of the right shape and the same cost.
///
/// It is random rather than fixed: a constant would be a recognisable marker in
/// memory, and reusing one across runs would let an attacker confirm which
/// protection failed by watching for it.
fn decoy32() -> [u8; 32] {
    let mut b = [0u8; 32];
    if nyedarch_crypto::rng::RandomSource::fill(&nyedarch_crypto::rng::OsRandom, &mut b).is_err() {
        // Even a failed CSPRNG must not yield a predictable value that could
        // accidentally match anything; derive from time instead.
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(1);
        for (i, x) in b.iter_mut().enumerate() {
            *x = ((t >> (i % 16)) as u8) ^ (i as u8).wrapping_mul(31);
        }
    }
    b
}

/// Minimal, dependency-light bincode decode used in the runtime path.
fn bincode_decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Option<T> {
    // We reuse bincode via nyedarch-package's dependency graph indirectly; to keep
    // the runtime crate lean we re-declare the call through bincode here.
    bincode::deserialize(bytes).ok()
}

/// One-shot destruction (spec §35/§37): best-effort deletion of the capsule
/// binary after a verified successful extraction. Documented limitation: this
/// cannot guarantee secure erasure on SSD/CoW filesystems; the cryptographic
/// design does not rely on it.
pub fn one_shot_destroy(self_path: &Path) {
    let _ = std::fs::remove_file(self_path);
}

pub use nyedarch_core::Policy as RuntimePolicy;
