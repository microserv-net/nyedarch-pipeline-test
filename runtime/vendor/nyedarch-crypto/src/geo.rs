//! Deterministic geographic quantization for the optional location factor.
//!
//! Spec §20/§21: raw GPS is unstable and low-entropy, so location is a *policy*
//! factor, not a source of key strength. We map an accepted position to a
//! stable cell identifier that reproduces across small position jitter, and we
//! reject readings whose reported accuracy is worse than the configured
//! tolerance.
//!
//! LIMITATION (documented, not hidden — spec §78): a uniform lat/lon grid has
//! boundary sensitivity (two nearby points either side of a cell edge quantize
//! differently). The production target is an H3/S2 hierarchical cell system,
//! abstracted behind `quantize` so it can be swapped without touching the key
//! schedule. This is recorded as decision ADR-0003.

use crate::error::{CryptoError, Result};

/// Configured acceptance tolerance, in meters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ToleranceMeters(pub u32);

/// A location reading as delivered by an OS/browser provider (spec §19: the
/// runtime obtains this automatically; there is no manual coordinate entry).
#[derive(Clone, Copy, Debug)]
pub struct Reading {
    pub lat_deg: f64,
    pub lon_deg: f64,
    /// Provider-reported horizontal accuracy in meters (1-sigma-ish).
    pub accuracy_m: f64,
}

const EARTH_RADIUS_M: f64 = 6_371_000.0;

/// Quantize an accepted reading to a stable cell id.
///
/// Fails closed if the reported accuracy is worse than tolerance (spec §20:
/// "do not silently accept poor-quality location information").
pub fn quantize(reading: &Reading, tol: ToleranceMeters) -> Result<Vec<u8>> {
    if !reading.lat_deg.is_finite() || !reading.lon_deg.is_finite() || !reading.accuracy_m.is_finite() {
        return Err(CryptoError::Malformed);
    }
    if reading.lat_deg.abs() > 90.0 || reading.lon_deg.abs() > 180.0 {
        return Err(CryptoError::Malformed);
    }
    let tol_m = tol.0 as f64;
    if tol_m <= 0.0 {
        return Err(CryptoError::Param);
    }
    // Reject inadequate accuracy (spec §20).
    if reading.accuracy_m > tol_m {
        return Err(CryptoError::Authorization);
    }

    // Grid step in radians for latitude; longitude step scaled by cos(lat) so
    // cells stay ~tol_m wide in physical distance regardless of latitude.
    let lat_rad = reading.lat_deg.to_radians();
    let lat_step = tol_m / EARTH_RADIUS_M; // radians
    let cos_lat = lat_rad.cos().abs().max(1e-9);
    let lon_step = tol_m / (EARTH_RADIUS_M * cos_lat); // radians

    let lat_cell = (lat_rad / lat_step).round() as i64;
    let lon_cell = (reading.lon_deg.to_radians() / lon_step).round() as i64;

    // Cell id also binds the tolerance so different tolerances never collide.
    let mut id = Vec::with_capacity(8 + 8 + 4);
    id.extend_from_slice(&lat_cell.to_le_bytes());
    id.extend_from_slice(&lon_cell.to_le_bytes());
    id.extend_from_slice(&tol.0.to_le_bytes());
    Ok(id)
}
