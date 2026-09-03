//! Adversarial integration tests for the core security invariant (spec §32,
//! §64, exec §7): bypassing/patching authorization must NOT yield the payload
//! key. We model each "attack" by feeding compose the contribution an attacker
//! could actually supply and asserting the payload stays cryptographically
//! inaccessible.

use nyedarch_crypto::{
    compose, passphrase_key, version, Argon2Params, Binding, Capsule, Contributions, PolicyFlags,
};

fn params() -> Argon2Params {
    Argon2Params { m_cost: 8, t_cost: 1, p_cost: 1 }
}

fn binding() -> Binding {
    Binding {
        package_id: *b"pkgpkgpkgpkgpkg1",
        runtime_binding: [0x5a; 32],
        crypto_version: version::CRYPTO_VERSION,
    }
}

/// Build a package that requires machine + passphrase + location + time.
fn all_factors_flags() -> PolicyFlags {
    PolicyFlags::MACHINE | PolicyFlags::PASSPHRASE | PolicyFlags::LOCATION | PolicyFlags::TIME
}

fn build_contrib(
    salt: &[u8],
    machine: [u8; 32],
    pass: &[u8],
    cell: Option<Vec<u8>>,
    win: Option<Vec<u8>>,
) -> Contributions {
    Contributions {
        machine_secret: Some(machine),
        passphrase_key: Some(passphrase_key(pass, salt, params()).unwrap()),
        location_cell: cell,
        time_window: win,
    }
}

#[test]
fn authorized_open_succeeds_and_binds_runtime() {
    let salt = [0x11u8; 32];
    let b = binding();
    let flags = all_factors_flags();
    let machine = [0xA1u8; 32];
    let cell = Some(b"cell-A".to_vec());
    let win = Some(b"win-1".to_vec());

    let c = build_contrib(&salt, machine, b"correct horse", cell.clone(), win.clone());
    let sealed = Capsule::seal(b"TOP SECRET PAYLOAD", &salt, &b, flags, &c).unwrap();

    // Legitimate runtime, correct factors -> plaintext.
    let c2 = build_contrib(&salt, machine, b"correct horse", cell.clone(), win.clone());
    let out = Capsule::open(&sealed, &salt, &b, flags, &c2).unwrap();
    assert_eq!(out.as_slice(), b"TOP SECRET PAYLOAD");

    // Transplant into a DIFFERENT runtime (different runtime_binding): fails,
    // even with all correct factors (spec §27).
    let mut b_other = binding();
    b_other.runtime_binding = [0x01; 32];
    let c3 = build_contrib(&salt, machine, b"correct horse", cell, win);
    assert!(Capsule::open(&sealed, &salt, &b_other, flags, &c3).is_err());
}

#[test]
fn wrong_fingerprint_secret_denies_payload() {
    let salt = [0x22u8; 32];
    let b = binding();
    let flags = PolicyFlags::MACHINE | PolicyFlags::PASSPHRASE;
    let c = build_contrib(&salt, [0xA1; 32], b"pw", None, None);
    let sealed = Capsule::seal(b"data", &salt, &b, flags, &c).unwrap();

    // Attacker who did not match a trusted fingerprint supplies a wrong secret.
    let bad = build_contrib(&salt, [0x00; 32], b"pw", None, None);
    assert!(Capsule::open(&sealed, &salt, &b, flags, &bad).is_err());
}

#[test]
fn wrong_passphrase_denies_payload() {
    let salt = [0x33u8; 32];
    let b = binding();
    let flags = PolicyFlags::MACHINE | PolicyFlags::PASSPHRASE;
    let c = build_contrib(&salt, [0xA1; 32], b"right", None, None);
    let sealed = Capsule::seal(b"data", &salt, &b, flags, &c).unwrap();
    let bad = build_contrib(&salt, [0xA1; 32], b"wrong", None, None);
    assert!(Capsule::open(&sealed, &salt, &b, flags, &bad).is_err());
}

#[test]
fn missing_enabled_factor_fails_closed() {
    // Policy requires TIME, but the runtime supplies no window (time gate
    // failed). Composition must refuse to produce a key (spec §29 fail closed),
    // NOT fall back to a machine+passphrase-only key.
    let salt = [0x44u8; 32];
    let b = binding();
    let flags = PolicyFlags::MACHINE | PolicyFlags::PASSPHRASE | PolicyFlags::TIME;
    let good = build_contrib(&salt, [0xA1; 32], b"pw", None, Some(b"win".to_vec()));
    let sealed = Capsule::seal(b"data", &salt, &b, flags, &good).unwrap();

    let no_time = build_contrib(&salt, [0xA1; 32], b"pw", None, None);
    let err = compose::derive_payload_key(&salt, &b, flags, &no_time).unwrap_err();
    // It is an authorization failure, and crucially open cannot proceed.
    assert!(matches!(err, nyedarch_crypto::CryptoError::Authorization));
    assert!(Capsule::open(&sealed, &salt, &b, flags, &no_time).is_err());
}

#[test]
fn attacker_cannot_downgrade_policy_to_drop_a_factor() {
    // Sealed under LOCATION-enabled policy. Attacker re-derives claiming a
    // machine+passphrase-only policy (dropped the location factor) to avoid
    // needing the location. AAD/info mismatch -> different key -> AEAD fails.
    let salt = [0x55u8; 32];
    let b = binding();
    let strong = PolicyFlags::MACHINE | PolicyFlags::PASSPHRASE | PolicyFlags::LOCATION;
    let c = build_contrib(&salt, [0xA1; 32], b"pw", Some(b"cell".to_vec()), None);
    let sealed = Capsule::seal(b"data", &salt, &b, strong, &c).unwrap();

    let weak = PolicyFlags::MACHINE | PolicyFlags::PASSPHRASE;
    let c_weak = build_contrib(&salt, [0xA1; 32], b"pw", None, None);
    assert!(Capsule::open(&sealed, &salt, &b, weak, &c_weak).is_err());
}

#[test]
fn ciphertext_tamper_is_detected() {
    let salt = [0x66u8; 32];
    let b = binding();
    let flags = PolicyFlags::MACHINE | PolicyFlags::PASSPHRASE;
    let c = build_contrib(&salt, [0xA1; 32], b"pw", None, None);
    let mut sealed = Capsule::seal(b"data", &salt, &b, flags, &c).unwrap();
    sealed.ct[0] ^= 0xff;
    let c2 = build_contrib(&salt, [0xA1; 32], b"pw", None, None);
    assert!(Capsule::open(&sealed, &salt, &b, flags, &c2).is_err());
}
