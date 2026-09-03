// GENERATED per-build NYEDArch runtime — build nonce 5ab657e5451710b0.
// This file is assembled by the generator, not shipped as a plaintext template.
use std::io::Read;
use std::path::PathBuf;
use nyedarch_runtime::{run, one_shot_destroy, Capsule, LocalTime, LocationProvider, Outcome, PassphraseProvider, SystemLocation};
use nyedarch_crypto::timewin::DailySchedule;
use zeroize::Zeroizing;

const PACKAGE: &[u8] = include_bytes!("../capsule.nyeda");
const BOOTSTRAP_KEY: [u8; 32] = [0xf4, 0x6d, 0x51, 0x55, 0x43, 0x69, 0xb7, 0x48, 0xcd, 0x7c, 0x41, 0xbd, 0xb3, 0xbc, 0xee, 0x43, 0x49, 0x20, 0x26, 0xda, 0xe5, 0x71, 0x8f, 0xe2, 0x9f, 0x5b, 0xdb, 0x3e, 0x78, 0x39, 0x74, 0x91];
// This runtime's own identity commitment (correction pass §4). It is asserted
// against the package header AND mixed into the policy-seal subkey, so another
// runtime cannot open this package's authorization record.
const RUNTIME_COMMITMENT: [u8; 32] = [0xa5, 0x20, 0xbc, 0xa9, 0x29, 0xf9, 0x7a, 0x48, 0xfa, 0xb2, 0x2b, 0xd5, 0xff, 0x67, 0xa8, 0xed, 0x10, 0xa1, 0x4e, 0xbb, 0x0d, 0x5a, 0x61, 0x97, 0xf9, 0xa3, 0xd5, 0x9d, 0xc1, 0x82, 0xbd, 0xf0];
const BUILD_NONCE: u64 = 0x5ab657e5451710b0;
const ONE_SHOT: bool = false;

struct StdinPass;
impl PassphraseProvider for StdinPass {
    fn passphrase(&self) -> Option<Zeroizing<Vec<u8>>> {
        // Prototype: read from NYEDARCH_PASSPHRASE env or stdin. The GUI supplies a
        // masked field. No manual location/time entry is ever offered (spec §33).
        if let Ok(p) = std::env::var("NYEDARCH_PASSPHRASE") {
            return Some(Zeroizing::new(p.into_bytes()));
        }
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s).ok()?;
        Some(Zeroizing::new(s.trim_end().as_bytes().to_vec()))
    }
}

fn main() {
    let _ = BUILD_NONCE;
    let out = std::env::args().nth(1).map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("./nyeda-extracted"));
    let cap = Capsule {
        package: PACKAGE,
        bootstrap_key: BOOTSTRAP_KEY,
        runtime_commitment: RUNTIME_COMMITMENT,
        schedule: None,
        location_tolerance_m: None,
        out_dir: out,
    };
    let location: Option<&dyn LocationProvider> = None;
    let creator = std::env::var("NYEDARCH_CREATOR").is_ok();
    let mut trace = |s| eprintln!("[state] {:?}", s);
    let t: Option<&mut dyn FnMut(nyedarch_runtime::State)> = if creator { Some(&mut trace) } else { None };
    match run(&cap, &StdinPass, location, &LocalTime, t) {
        Outcome::Success { files, dirs, bytes, out_dir } => {
            println!("NYEDArch: extraction complete - {} files, {} dirs, {} bytes -> {}",
                files, dirs, bytes, out_dir.display());
            if ONE_SHOT {
                // Only after verified extraction (spec §37). Best-effort:
                // cannot guarantee erasure on SSD/CoW filesystems.
                if let Ok(me) = std::env::current_exe() {
                    one_shot_destroy(&me);
                }
            }
        }
        Outcome::Failed => {
            // Single generic message (spec §51): no authorization oracle.
            eprintln!("Authorization failed.");
            std::process::exit(1);
        }
    }
}
