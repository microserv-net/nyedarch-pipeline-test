//! Optional time factor (spec §22-§24).
//!
//! The runtime computes the current time window itself and turns it into a
//! stable window id; there is no plaintext "correct time" comparison to patch
//! (spec §24). Any time inside the same tolerance window yields the same id, so
//! the key reproduces; outside the window there is no id and the factor fails.
//!
//! PROTOTYPE: local system clock only (spec §23). The `TimeSource` seam lets a
//! future authenticated time provider replace it without redesign.
//!
//! FUTURE — LICENSE SERVER: authenticated server time.

use crate::error::{CryptoError, Result};

/// Abstraction over "what time is it" so the local clock can be replaced later.
pub trait TimeSource {
    /// Seconds since Unix epoch (UTC).
    fn now_unix(&self) -> i64;
}

/// Prototype local-clock source.
pub struct LocalClock;
impl TimeSource for LocalClock {
    fn now_unix(&self) -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
}

/// A daily schedule: one or more times-of-day (minutes past local midnight),
/// with a symmetric tolerance window, in a fixed timezone offset.
#[derive(Clone, Debug)]
pub struct DailySchedule {
    /// Times of day in minutes past midnight, e.g. 14:00 -> 840.
    pub slots_minutes: Vec<u32>,
    /// Symmetric tolerance in minutes (e.g. 15 => ±15 min).
    pub tolerance_minutes: u32,
    /// Fixed timezone offset from UTC in minutes (e.g. IST +330).
    pub tz_offset_minutes: i32,
}

impl DailySchedule {
    /// Return the stable window id if `now` falls inside any slot's tolerance
    /// window, else `Authorization` failure (fail closed).
    pub fn window_id(&self, now_unix: i64) -> Result<Vec<u8>> {
        if self.slots_minutes.is_empty() || self.tolerance_minutes == 0 {
            return Err(CryptoError::Param);
        }
        let tol_s = self.tolerance_minutes as i64 * 60;
        let local = now_unix + self.tz_offset_minutes as i64 * 60;
        let day = local.div_euclid(86_400);
        let sec_of_day = local.rem_euclid(86_400);

        // Check each slot on the current local day and the two neighbours, so a
        // window straddling midnight still matches.
        for d in [day - 1, day, day + 1] {
            for &slot in &self.slots_minutes {
                let slot_s = slot as i64 * 60;
                let slot_instant = d * 86_400 + slot_s; // local seconds
                let this_instant = day * 86_400 + sec_of_day;
                if (this_instant - slot_instant).abs() <= tol_s {
                    // Window id = the canonical SLOT (time-of-day), never the
                    // absolute instant.
                    //
                    // This is deliberately day-invariant. A schedule like
                    // "every day at 14:00 ±15" must derive the SAME key on every
                    // qualifying day; embedding the absolute day would silently
                    // restrict the capsule to the single day it was built, which
                    // is not the configured policy (spec §22 recurring
                    // schedules).
                    //
                    // Consequence, stated plainly: the time protection constrains
                    // *when within a day* a capsule opens, not *which day*. It is
                    // a recurring-window policy factor, not an expiry mechanism.
                    // Date-bounded validity is a separate feature and is not
                    // claimed here.
                    let mut id = Vec::with_capacity(4 + 4 + 4);
                    id.extend_from_slice(&slot.to_le_bytes());
                    id.extend_from_slice(&self.tolerance_minutes.to_le_bytes());
                    id.extend_from_slice(&self.tz_offset_minutes.to_le_bytes());
                    return Ok(id);
                }
            }
        }
        Err(CryptoError::Authorization)
    }
}

/// Compute the window id for a slot without consulting a clock. Builder-side
/// use only: the builder must commit to the same canonical window the runtime
/// will independently recompute from its own clock.
impl DailySchedule {
    pub fn window_id_for_slot(&self, slot_minutes: u32) -> Result<Vec<u8>> {
        if !self.slots_minutes.contains(&slot_minutes) || self.tolerance_minutes == 0 {
            return Err(CryptoError::Param);
        }
        let mut id = Vec::with_capacity(12);
        id.extend_from_slice(&slot_minutes.to_le_bytes());
        id.extend_from_slice(&self.tolerance_minutes.to_le_bytes());
        id.extend_from_slice(&self.tz_offset_minutes.to_le_bytes());
        Ok(id)
    }
}
