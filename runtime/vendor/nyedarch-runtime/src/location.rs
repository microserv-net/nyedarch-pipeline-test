//! Runtime-side location provider. The actual platform acquisition lives in
//! `nyedarch-platform` so the builder can capture a location without depending on
//! the runtime (spec §29 separation). No manual-entry fallback exists on either
//! side (spec §33).

use nyedarch_crypto::geo::Reading;

use crate::LocationProvider;

pub struct SystemLocation;

impl LocationProvider for SystemLocation {
    fn reading(&self) -> Option<Reading> {
        nyedarch_platform::acquire_location()
    }
}
