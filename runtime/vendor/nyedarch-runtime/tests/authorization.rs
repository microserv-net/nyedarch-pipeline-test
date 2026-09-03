//! End-to-end authorization tests for the runtime state machine (spec §63).
//!
//! These drive the REAL state machine over REAL sealed packages. Every negative
//! case asserts two things: authorization is denied, AND no plaintext reaches
//! the output directory.

use std::fs;
use std::path::PathBuf;

use nyedarch_core::{Policy, PolicyEntry, PolicyRecord};
use nyedarch_crypto::geo::{Reading, ToleranceMeters};
use nyedarch_crypto::timewin::DailySchedule;
use nyedarch_crypto::{compose, passphrase_key, version, Argon2Params, Binding, Contributions};
use nyedarch_package::format::*;
use nyedarch_package::{collect, seal_package};
use nyedarch_runtime::{run, Capsule, LocationProvider, Outcome, PassphraseProvider, TimeProvider};
use zeroize::Zeroizing;

const ARGON: Argon2Params = Argon2Params { m_cost: 8, t_cost: 1, p_cost: 1 };
const SECRET_TEXT: &[u8] = b"TOP SECRET PAYLOAD MARKER";

fn tmpdir(tag: &str) -> PathBuf {
    let mut d = std::env::temp_dir();
    d.push(format!(
        "nyeda-it-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir_all(&d).unwrap();
    d
}

struct Pass(&'static str);
impl PassphraseProvider for Pass {
    fn passphrase(&self) -> Option<Zeroizing<Vec<u8>>> {
        Some(Zeroizing::new(self.0.as_bytes().to_vec()))
    }
}
struct NoPass;
impl PassphraseProvider for NoPass {
    fn passphrase(&self) -> Option<Zeroizing<Vec<u8>>> {
        None
    }
}

struct FixedLoc(Reading);
impl LocationProvider for FixedLoc {
    fn reading(&self) -> Option<Reading> {
        Some(self.0)
    }
}
struct NoLoc;
impl LocationProvider for NoLoc {
    fn reading(&self) -> Option<Reading> {
        None
    }
}

struct FixedTime(i64);
impl TimeProvider for FixedTime {
    fn now_unix(&self) -> Option<i64> {
        Some(self.0)
    }
}

/// A built capsule fixture plus everything needed to run it.
struct Fixture {
    package: Vec<u8>,
    bootstrap_key: [u8; 32],
    runtime_commitment: [u8; 32],
    schedule: Option<DailySchedule>,
    location_tolerance_m: Option<u32>,
    dir: PathBuf,
}

/// Build a real sealed package for `machine_id`, with the given protections.
fn build(
    tag: &str,
    machine_id: [u8; 32],
    passphrase: &str,
    schedule: Option<DailySchedule>,
    location: Option<(u32, Reading)>,
) -> Fixture {
    let dir = tmpdir(tag);
    let src = dir.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("secret.txt"), SECRET_TEXT).unwrap();

    let package_salt = [0x5Au8; 32];
    let bootstrap_key = [0xB0u8; 32];
    let runtime_commitment = [0xC1u8; 32];
    let package_id = *b"pkg-integration1";
    let machine_secret = [0x77u8; 32];

    let policy = Policy {
        location: location.is_some(),
        time: schedule.is_some(),
        one_shot: false,
    };
    let binding = Binding { package_id, runtime_binding: runtime_commitment, crypto_version: version::CRYPTO_VERSION };
    let flags = policy.to_flags();
    let context = compose::payload_aad(&binding, flags);

    let record = PolicyRecord {
        entries: vec![PolicyEntry { fingerprint_id: machine_id, factor_secret: machine_secret, labels: vec!["test".into()] }],
    };
    let record_bytes = bincode::serialize(&record).unwrap();
    let sealed_policy = nyedarch_crypto::policy_seal::seal_record(
        &bootstrap_key, &runtime_commitment, &package_salt, &context, &record_bytes,
    )
    .unwrap()
    .to_bytes();

    let location_cell = location.map(|(tol, r)| nyedarch_crypto::geo::quantize(&r, ToleranceMeters(tol)).unwrap());
    let time_window = schedule.as_ref().map(|s| s.window_id_for_slot(s.slots_minutes[0]).unwrap());

    let contrib = Contributions {
        machine_secret: Some(machine_secret),
        passphrase_key: Some(passphrase_key(passphrase.as_bytes(), &package_salt, ARGON).unwrap()),
        location_cell,
        time_window,
    };
    let key = compose::derive_payload_key(&package_salt, &binding, flags, &contrib).unwrap();

    let (manifest, files) = collect(&[src]).unwrap();
    let header = Header {
        crypto_version: version::CRYPTO_VERSION,
        package_id,
        runtime_binding: runtime_commitment,
        policy,
        argon: ARGON.into(),
        package_salt,
        compression: COMPRESSION_DEFLATE,
        chunk_size: 4096,
    };
    let package = seal_package(&header, &sealed_policy, &key, &manifest, &files).unwrap();

    Fixture {
        package,
        bootstrap_key,
        runtime_commitment,
        schedule,
        location_tolerance_m: location.map(|(t, _)| t),
        dir,
    }
}

impl Fixture {
    fn capsule<'a>(&'a self, out: &PathBuf) -> Capsule<'a> {
        Capsule {
            package: &self.package,
            bootstrap_key: self.bootstrap_key,
            runtime_commitment: self.runtime_commitment,
            schedule: self.schedule.clone(),
            location_tolerance_m: self.location_tolerance_m,
            out_dir: out.clone(),
        }
    }
}

/// Assert denial AND that nothing plaintext was written.
fn assert_denied(outcome: Outcome, out: &PathBuf) {
    match outcome {
        Outcome::Success { .. } => panic!("authorization should have been denied"),
        Outcome::Failed => {}
    }
    if out.exists() {
        let leaked: Vec<_> = walk(out);
        assert!(leaked.is_empty(), "plaintext leaked on failure: {leaked:?}");
    }
}

fn walk(p: &PathBuf) -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Ok(rd) = fs::read_dir(p) {
        for e in rd.flatten() {
            let path = e.path();
            if path.is_dir() {
                v.extend(walk(&path));
            } else {
                v.push(path);
            }
        }
    }
    v
}

const OTHER_MACHINE: [u8; 32] = [0x22u8; 32];

// NOTE: the runtime captures the REAL machine fingerprint, which no test can
// predict. So these tests exercise the state machine by building packages
// trusting the actual live fingerprint (authorized cases) or a fabricated one
// (denial cases).
fn live_id() -> [u8; 32] {
    nyedarch_fingerprint::capture().id
}

#[test]
fn authorized_run_extracts_payload() {
    let f = build("ok", live_id(), "correct-pass", None, None);
    let out = f.dir.join("out");
    let r = run(&f.capsule(&out), &Pass("correct-pass"), None, &FixedTime(0), None);
    match r {
        Outcome::Success { files, .. } => assert_eq!(files, 1),
        Outcome::Failed => panic!("authorized run must succeed"),
    }
    assert_eq!(fs::read(out.join("src/secret.txt")).unwrap(), SECRET_TEXT);
}

#[test]
fn wrong_passphrase_is_denied_and_leaks_nothing() {
    let f = build("badpass", live_id(), "correct-pass", None, None);
    let out = f.dir.join("out");
    assert_denied(run(&f.capsule(&out), &Pass("WRONG"), None, &FixedTime(0), None), &out);
}

#[test]
fn untrusted_machine_is_denied() {
    // Package trusts a machine that is NOT this one.
    let f = build("badmachine", OTHER_MACHINE, "p", None, None);
    let out = f.dir.join("out");
    assert_denied(run(&f.capsule(&out), &Pass("p"), None, &FixedTime(0), None), &out);
}

#[test]
fn unavailable_passphrase_fails_closed() {
    let f = build("nopass", live_id(), "p", None, None);
    let out = f.dir.join("out");
    assert_denied(run(&f.capsule(&out), &NoPass, None, &FixedTime(0), None), &out);
}

#[test]
fn transplanted_package_is_denied() {
    // Runtime A's commitment against package B: the policy record cannot unseal.
    let f = build("transplant", live_id(), "p", None, None);
    let out = f.dir.join("out");
    let mut cap = f.capsule(&out);
    cap.runtime_commitment = [0xEEu8; 32]; // a different runtime
    assert_denied(run(&cap, &Pass("p"), None, &FixedTime(0), None), &out);
}

#[test]
fn tampered_payload_fails_authentication() {
    let f = build("tamper", live_id(), "p", None, None);
    let out = f.dir.join("out");
    let mut pkg = f.package.clone();
    let n = pkg.len();
    pkg[n - 20] ^= 0xff; // flip a ciphertext byte
    let cap = Capsule {
        package: &pkg,
        bootstrap_key: f.bootstrap_key,
        runtime_commitment: f.runtime_commitment,
        schedule: None,
        location_tolerance_m: None,
        out_dir: out.clone(),
    };
    assert_denied(run(&cap, &Pass("p"), None, &FixedTime(0), None), &out);
}

#[test]
fn corrupted_header_fails_closed() {
    let f = build("badheader", live_id(), "p", None, None);
    let out = f.dir.join("out");
    let mut pkg = f.package.clone();
    pkg[3] ^= 0xff; // break the magic
    let cap = Capsule {
        package: &pkg,
        bootstrap_key: f.bootstrap_key,
        runtime_commitment: f.runtime_commitment,
        schedule: None,
        location_tolerance_m: None,
        out_dir: out.clone(),
    };
    assert_denied(run(&cap, &Pass("p"), None, &FixedTime(0), None), &out);
}

// --- location protection ---------------------------------------------------------

const HERE: Reading = Reading { lat_deg: 12.9716, lon_deg: 77.5946, accuracy_m: 20.0 };

#[test]
fn location_protection_accepts_same_region() {
    let f = build("loc-ok", live_id(), "p", None, Some((150, HERE)));
    let out = f.dir.join("out");
    let r = run(&f.capsule(&out), &Pass("p"), Some(&FixedLoc(HERE)), &FixedTime(0), None);
    assert!(matches!(r, Outcome::Success { .. }));
}

#[test]
fn location_protection_denies_different_region() {
    let f = build("loc-far", live_id(), "p", None, Some((150, HERE)));
    let out = f.dir.join("out");
    let far = Reading { lat_deg: 48.8566, lon_deg: 2.3522, accuracy_m: 20.0 }; // Paris
    assert_denied(run(&f.capsule(&out), &Pass("p"), Some(&FixedLoc(far)), &FixedTime(0), None), &out);
}

#[test]
fn location_protection_rejects_poor_accuracy() {
    let f = build("loc-acc", live_id(), "p", None, Some((100, HERE)));
    let out = f.dir.join("out");
    // Right place, but the fix is far too coarse to prove it (spec §20).
    let vague = Reading { accuracy_m: 5000.0, ..HERE };
    assert_denied(run(&f.capsule(&out), &Pass("p"), Some(&FixedLoc(vague)), &FixedTime(0), None), &out);
}

#[test]
fn location_protection_fails_closed_without_provider() {
    let f = build("loc-none", live_id(), "p", None, Some((100, HERE)));
    let out = f.dir.join("out");
    assert_denied(run(&f.capsule(&out), &Pass("p"), Some(&NoLoc), &FixedTime(0), None), &out);
    // And with no provider supplied at all.
    let out2 = f.dir.join("out2");
    assert_denied(run(&f.capsule(&out2), &Pass("p"), None, &FixedTime(0), None), &out2);
}

// --- time protection -------------------------------------------------------------

fn schedule_at(slot_min: u32, tol: u32) -> DailySchedule {
    DailySchedule { slots_minutes: vec![slot_min], tolerance_minutes: tol, tz_offset_minutes: 0 }
}

/// A UTC instant at `hh:mm` on an arbitrary fixed day.
fn instant_at(slot_min: u32) -> i64 {
    let day = 19_800i64; // fixed day index, value irrelevant (day-invariant)
    day * 86_400 + slot_min as i64 * 60
}

#[test]
fn time_protection_accepts_inside_window() {
    let f = build("time-ok", live_id(), "p", Some(schedule_at(840, 15)), None);
    let out = f.dir.join("out");
    let r = run(&f.capsule(&out), &Pass("p"), None, &FixedTime(instant_at(840) + 5 * 60), None);
    assert!(matches!(r, Outcome::Success { .. }));
}

#[test]
fn time_protection_denies_outside_window() {
    let f = build("time-bad", live_id(), "p", Some(schedule_at(840, 15)), None);
    let out = f.dir.join("out");
    assert_denied(run(&f.capsule(&out), &Pass("p"), None, &FixedTime(instant_at(840) + 90 * 60), None), &out);
}

#[test]
fn time_protection_is_day_invariant() {
    // A recurring daily schedule must still open a year later.
    let f = build("time-daily", live_id(), "p", Some(schedule_at(840, 15)), None);
    let out = f.dir.join("out");
    let r = run(&f.capsule(&out), &Pass("p"), None, &FixedTime(instant_at(840) + 365 * 86_400), None);
    assert!(matches!(r, Outcome::Success { .. }), "daily schedule must recur");
}

#[test]
fn all_protections_together_require_every_factor() {
    let sched = schedule_at(600, 10);
    let f = build("all", live_id(), "p", Some(sched), Some((150, HERE)));
    let out = f.dir.join("out");
    let good_time = instant_at(600);

    // Everything correct -> success.
    let r = run(&f.capsule(&out), &Pass("p"), Some(&FixedLoc(HERE)), &FixedTime(good_time), None);
    assert!(matches!(r, Outcome::Success { .. }));

    // Each factor broken in turn -> denial. AND semantics (spec §5).
    let o1 = f.dir.join("o1");
    assert_denied(run(&f.capsule(&o1), &Pass("WRONG"), Some(&FixedLoc(HERE)), &FixedTime(good_time), None), &o1);

    let o2 = f.dir.join("o2");
    let far = Reading { lat_deg: 48.8566, lon_deg: 2.3522, accuracy_m: 20.0 };
    assert_denied(run(&f.capsule(&o2), &Pass("p"), Some(&FixedLoc(far)), &FixedTime(good_time), None), &o2);

    let o3 = f.dir.join("o3");
    assert_denied(run(&f.capsule(&o3), &Pass("p"), Some(&FixedLoc(HERE)), &FixedTime(good_time + 3600), None), &o3);
}

// --- constant-shape authorization -------------------------------------------

/// Record the states a run passes through.
fn trace_of(
    f: &Fixture,
    out: &PathBuf,
    pass: &dyn PassphraseProvider,
    loc: Option<&dyn LocationProvider>,
    time: &dyn TimeProvider,
    commitment: Option<[u8; 32]>,
) -> Vec<nyedarch_runtime::State> {
    let mut cap = f.capsule(out);
    if let Some(c) = commitment {
        cap.runtime_commitment = c;
    }
    let mut seen = Vec::new();
    let mut cb = |s| seen.push(s);
    let _ = run(&cap, pass, loc, time, Some(&mut cb));
    seen
}

/// Every denial must reach the same depth.
///
/// Before this, a run returned as soon as a protection failed, so denial
/// latency revealed which one: a binding failure returned in ~2 ms while a
/// passphrase failure took ~100 ms because only the latter paid the Argon2id
/// cost. An attacker learned whether they had cleared the machine protection.
#[test]
fn every_denial_reaches_the_same_final_states() {
    use nyedarch_runtime::State;
    let sched = schedule_at(600, 10);
    let f = build("uniform", live_id(), "right", Some(sched), Some((150, HERE)));
    let good_time = instant_at(600);
    let far = Reading { lat_deg: 48.8566, lon_deg: 2.3522, accuracy_m: 20.0 };

    let cases: Vec<(&str, Vec<State>)> = vec![
        (
            "wrong binding",
            trace_of(&f, &f.dir.join("a"), &Pass("right"), Some(&FixedLoc(HERE)), &FixedTime(good_time), Some([0xEE; 32])),
        ),
        (
            "wrong passphrase",
            trace_of(&f, &f.dir.join("b"), &Pass("WRONG"), Some(&FixedLoc(HERE)), &FixedTime(good_time), None),
        ),
        (
            "no passphrase",
            trace_of(&f, &f.dir.join("c"), &NoPass, Some(&FixedLoc(HERE)), &FixedTime(good_time), None),
        ),
        (
            "wrong region",
            trace_of(&f, &f.dir.join("d"), &Pass("right"), Some(&FixedLoc(far)), &FixedTime(good_time), None),
        ),
        (
            "no location provider",
            trace_of(&f, &f.dir.join("e"), &Pass("right"), Some(&NoLoc), &FixedTime(good_time), None),
        ),
        (
            "outside the time window",
            trace_of(&f, &f.dir.join("g"), &Pass("right"), Some(&FixedLoc(HERE)), &FixedTime(good_time + 3600), None),
        ),
    ];

    for (name, states) in &cases {
        // The expensive stage must run in every case: skipping it is what
        // created the timing difference.
        assert!(
            states.contains(&State::PassphraseAcquisition),
            "{name}: returned before the passphrase stage, which reintroduces the oracle"
        );
        assert!(
            states.contains(&State::KeyDerivation),
            "{name}: returned before key derivation"
        );
        assert!(states.contains(&State::FailClosed), "{name}: must fail closed");
    }

    // And they must be indistinguishable from one another.
    let first = &cases[0].1;
    for (name, states) in &cases[1..] {
        assert_eq!(
            states, first,
            "{name}: state trace differs from the first denial, so the depth reached still leaks which protection failed"
        );
    }
}

/// The decoys must not become a bypass: a denial still produces no output.
#[test]
fn decoys_never_authorize() {
    let f = build("decoy", OTHER_MACHINE, "p", None, None);
    let out = f.dir.join("out");
    // Untrusted machine: the machine protection substitutes a random decoy.
    assert_denied(run(&f.capsule(&out), &Pass("p"), None, &FixedTime(0), None), &out);
}
