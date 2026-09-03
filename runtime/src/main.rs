// GENERATED per-build NYEDArch runtime — build nonce bbe8e954ca0288aa.
// This file is assembled by the generator, not shipped as a plaintext template.
use std::io::Read;
use std::path::PathBuf;
use nyedarch_runtime::{run, one_shot_destroy, Capsule, LocalTime, LocationProvider, Outcome, PassphraseProvider, SystemLocation};
use nyedarch_crypto::timewin::DailySchedule;
use zeroize::Zeroizing;

const PACKAGE: &[u8] = include_bytes!("../capsule.nyeda");
const BOOTSTRAP_KEY: [u8; 32] = [0x2f, 0xf5, 0xde, 0x0c, 0x85, 0x33, 0x36, 0x3a, 0x2b, 0x7f, 0xfd, 0x4d, 0xa9, 0x99, 0x24, 0x85, 0x7b, 0x80, 0xd6, 0x5e, 0xa5, 0xee, 0x65, 0x09, 0xa7, 0x23, 0xca, 0xa6, 0x72, 0x91, 0x79, 0xa2];
// This runtime's own identity commitment (correction pass §4). It is asserted
// against the package header AND mixed into the policy-seal subkey, so another
// runtime cannot open this package's authorization record.
const RUNTIME_COMMITMENT: [u8; 32] = [0x51, 0xae, 0x57, 0x42, 0x67, 0x2b, 0x37, 0x46, 0xec, 0x56, 0xea, 0x86, 0x18, 0xa8, 0x19, 0x37, 0x22, 0x80, 0xe0, 0x2f, 0x6d, 0x8e, 0xcf, 0x59, 0xdb, 0x15, 0xac, 0x74, 0xb8, 0xf6, 0x7c, 0x3c];
const BUILD_NONCE: u64 = 0xbbe8e954ca0288aa;
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
