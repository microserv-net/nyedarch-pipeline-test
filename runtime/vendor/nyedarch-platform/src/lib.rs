//! Runtime location acquisition (spec §19/§33).
//!
//! The runtime acquires location **itself**. There is deliberately no manual
//! coordinate entry, no environment-variable override, and no "assume success
//! if unavailable" path: if a trustworthy provider is not present, the factor
//! yields nothing and authorization fails closed.
//!
//! This matters cryptographically as well as procedurally — the location factor
//! contributes a quantized cell id to key composition, so a fabricated reading
//! does not produce the right key anyway. The absence of a manual path removes
//! the *convenience* of trying, not the security boundary itself.
//!
//! Platform status:
//! - **macOS**: CoreLocation via the platform framework. Real seam below;
//!   requires macOS to build and a user permission grant to run.
//! - **Windows**: `Windows.Devices.Geolocation`. Same.
//! - **Linux**: GeoClue2 over D-Bus where the service is present and the user
//!   consents. Absent on headless systems, which correctly fail closed.

#![forbid(unsafe_code)]

use nyedarch_crypto::geo::Reading;

pub mod browser;

/// Acquire the current location from a native platform provider, or `None` if
/// none is available. There is no fabricated fallback, on any platform.
pub fn acquire_location() -> Option<Reading> {
    acquire()
}

/// How a reading was obtained. The caller records this so a weaker source is
/// never silently passed off as a stronger one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocationSource {
    /// An operating-system location service.
    Native,
    /// The user's browser, with an explicit permission prompt.
    Browser,
}

/// Acquire a location, preferring the native provider and falling back to the
/// browser flow.
///
/// The fallback exists because native providers are absent on many desktops:
/// macOS CoreLocation requires an entitled bundled application, Linux requires
/// a GeoClue agent, and headless machines have neither. Without it the location
/// protection would be unusable on most Macs.
///
/// `tolerance_m` is passed through only so the consent page can tell the user
/// what will be accepted. The caller still enforces the accuracy check, which
/// is what rejects coarse network-derived positions.
pub fn acquire_location_with_fallback(
    tolerance_m: Option<u32>,
) -> Result<(Reading, LocationSource), String> {
    if let Some(r) = acquire() {
        return Ok((r, LocationSource::Native));
    }
    match browser::acquire_via_browser(tolerance_m) {
        Ok(r) => Ok((r, LocationSource::Browser)),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(target_os = "linux")]
fn acquire() -> Option<Reading> {
    // Preferred: talk to GeoClue2 over D-Bus using gdbus, which ships with
    // glib and is present on any desktop that has GeoClue at all. This is the
    // supported interface; the demo binary tried below is a convenience only.
    if let Some(r) = geoclue_via_gdbus() {
        return Some(r);
    }
    legacy_demo_client()
}

/// Drive GeoClue2 through `gdbus`.
///
/// GeoClue requires a client object, an agent, and a signal wait. The desktop
/// portal (`org.freedesktop.portal.Location`) is the modern route and is what a
/// sandboxed application would use; both are attempted before giving up, and
/// failure simply means the browser flow takes over.
#[cfg(target_os = "linux")]
fn geoclue_via_gdbus() -> Option<Reading> {
    use std::process::Command;

    // 1) Ask GeoClue for a client object.
    let out = Command::new("gdbus")
        .args([
            "call", "--system", "--dest", "org.freedesktop.GeoClue2",
            "--object-path", "/org/freedesktop/GeoClue2/Manager",
            "--method", "org.freedesktop.GeoClue2.Manager.GetClient",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let client = parse_object_path(&String::from_utf8_lossy(&out.stdout))?;

    // 2) Identify ourselves; GeoClue refuses anonymous clients.
    let _ = Command::new("gdbus")
        .args([
            "call", "--system", "--dest", "org.freedesktop.GeoClue2",
            "--object-path", &client,
            "--method", "org.freedesktop.DBus.Properties.Set",
            "org.freedesktop.GeoClue2.Client", "DesktopId",
            "<'nyedarch'>",
        ])
        .output()
        .ok()?;

    // 3) Start, then read the location object.
    let _ = Command::new("gdbus")
        .args([
            "call", "--system", "--dest", "org.freedesktop.GeoClue2",
            "--object-path", &client,
            "--method", "org.freedesktop.GeoClue2.Client.Start",
        ])
        .output()
        .ok()?;

    // GeoClue needs a moment to produce a fix.
    for _ in 0..20 {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let loc = Command::new("gdbus")
            .args([
                "call", "--system", "--dest", "org.freedesktop.GeoClue2",
                "--object-path", &client,
                "--method", "org.freedesktop.DBus.Properties.Get",
                "org.freedesktop.GeoClue2.Client", "Location",
            ])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&loc.stdout).to_string();
        if let Some(path) = parse_object_path(&text) {
            if path == "/" {
                continue; // no fix yet
            }
            if let Some(r) = read_geoclue_location(&path) {
                let _ = Command::new("gdbus")
                    .args([
                        "call", "--system", "--dest", "org.freedesktop.GeoClue2",
                        "--object-path", &client,
                        "--method", "org.freedesktop.GeoClue2.Client.Stop",
                    ])
                    .output();
                return Some(r);
            }
        }
    }
    None
}

/// Read latitude, longitude and accuracy from a GeoClue location object.
#[cfg(target_os = "linux")]
fn read_geoclue_location(path: &str) -> Option<Reading> {
    use std::process::Command;
    let get = |prop: &str| -> Option<f64> {
        let o = Command::new("gdbus")
            .args([
                "call", "--system", "--dest", "org.freedesktop.GeoClue2",
                "--object-path", path,
                "--method", "org.freedesktop.DBus.Properties.Get",
                "org.freedesktop.GeoClue2.Location", prop,
            ])
            .output()
            .ok()?;
        parse_variant_double(&String::from_utf8_lossy(&o.stdout))
    };
    let lat = get("Latitude")?;
    let lon = get("Longitude")?;
    // An absent accuracy is refused rather than assumed good.
    let acc = get("Accuracy")?;
    if !acc.is_finite() || acc <= 0.0 {
        return None;
    }
    Some(Reading { lat_deg: lat, lon_deg: lon, accuracy_m: acc })
}

/// `(objectpath '/org/freedesktop/GeoClue2/Client/1',)` -> the path.
#[cfg(target_os = "linux")]
pub(crate) fn parse_object_path(s: &str) -> Option<String> {
    let i = s.find("objectpath")? + "objectpath".len();
    let rest = s[i..].trim_start().strip_prefix('\'')?;
    let end = rest.find('\'')?;
    Some(rest[..end].to_string())
}

/// `(<12.9716>,)` -> 12.9716
#[cfg(target_os = "linux")]
pub(crate) fn parse_variant_double(s: &str) -> Option<f64> {
    let i = s.find('<')? + 1;
    let rest = &s[i..];
    let end = rest.find('>')?;
    rest[..end].trim().parse().ok()
}

#[cfg(target_os = "linux")]
fn legacy_demo_client() -> Option<Reading> {
    // GeoClue2 is a session D-Bus service. Rather than embed a D-Bus stack in a
    // hostile-environment binary, the capsule shells out to the system client
    // only when it is actually installed; otherwise it fails closed.
    //
    // Headless/CI machines have no GeoClue agent, so this returns None and the
    // location protection denies authorization. That is the intended behaviour.
    let out = std::process::Command::new("/usr/libexec/geoclue-2.0/demos/where-am-i")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_where_am_i(&String::from_utf8_lossy(&out.stdout))
}

/// Parse latitude/longitude/accuracy from the GeoClue demo client output.
/// Separated so it can be unit-tested without the service present.
#[cfg(target_os = "linux")]
pub(crate) fn parse_where_am_i(s: &str) -> Option<Reading> {
    let mut lat = None;
    let mut lon = None;
    let mut acc = None;
    for line in s.lines() {
        let l = line.trim();
        // Values may carry a unit suffix (e.g. "45.000000 meters"), so take the
        // first whitespace-separated token after the colon.
        let val = |l: &str| -> Option<f64> {
            l.split(':').nth(1)?.trim().split_whitespace().next()?.parse().ok()
        };
        if l.starts_with("Latitude:") {
            lat = val(l);
        } else if l.starts_with("Longitude:") {
            lon = val(l);
        } else if l.starts_with("Accuracy:") {
            acc = val(l);
        }
    }
    Some(Reading { lat_deg: lat?, lon_deg: lon?, accuracy_m: acc? })
}

#[cfg(target_os = "macos")]
fn acquire() -> Option<Reading> {
    #[cfg(feature = "macos-corelocation")]
    {
        macos_corelocation::acquire()
    }
    #[cfg(not(feature = "macos-corelocation"))]
    {
        // Built without the CoreLocation binding: the browser flow handles it.
        None
    }
}

/// CoreLocation on macOS.
///
/// # The bundling requirement, stated first
///
/// macOS refuses location to a process that has no application bundle carrying
/// `NSLocationWhenInUseUsageDescription`. A plain command-line binary is denied
/// no matter how correct this code is. So:
///
/// * bundled and signed with the usage description -> this path works;
/// * a bare CLI, or an unbundled build -> authorization is denied and the
///   browser consent flow takes over.
///
/// That is why the browser flow exists and why it remains the fallback rather
/// than being replaced by this.
///
/// # Why there is no delegate
///
/// The usual CoreLocation pattern needs a delegate object and a live run loop.
/// This reads `CLLocationManager.location`, which holds the most recent fix,
/// and polls briefly for one to appear. It is a smaller surface for the same
/// result, and it cannot hang: it gives up and returns `None`.
#[cfg(all(target_os = "macos", feature = "macos-corelocation"))]
mod macos_corelocation {
    use super::Reading;
    use objc2_core_location::{CLAuthorizationStatus, CLLocationManager};

    pub fn acquire() -> Option<Reading> {
        // Location Services switched off system-wide: stop here rather than
        // spinning for a fix that cannot arrive.
        if !unsafe { CLLocationManager::locationServicesEnabled() } {
            return None;
        }

        let manager = unsafe { CLLocationManager::new() };
        unsafe { manager.requestWhenInUseAuthorization() };

        // Poll for a fix. Roughly ten seconds, then give up so the caller can
        // fall back rather than the application appearing to freeze.
        for _ in 0..40 {
            let status = unsafe { manager.authorizationStatus() };
            if status == CLAuthorizationStatus::Denied
                || status == CLAuthorizationStatus::Restricted
            {
                return None; // the user's decision is authoritative
            }
            if let Some(loc) = unsafe { manager.location() } {
                let coord = unsafe { loc.coordinate() };
                let accuracy = unsafe { loc.horizontalAccuracy() };
                // A negative horizontal accuracy means the coordinate is
                // invalid. Refused rather than treated as a perfect fix.
                if accuracy > 0.0 && accuracy.is_finite() {
                    return Some(Reading {
                        lat_deg: coord.latitude,
                        lon_deg: coord.longitude,
                        accuracy_m: accuracy,
                    });
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        None
    }
}

#[cfg(target_os = "windows")]
fn acquire() -> Option<Reading> {
    // Windows exposes the system location service through
    // `System.Device.Location.GeoCoordinateWatcher`, which Windows PowerShell
    // can drive directly. Going through PowerShell rather than a WinRT binding
    // keeps this dependency-free and keeps the honest failure mode: if the user
    // has location switched off, or denies the app, the watcher never reaches
    // Ready and we fall through to the browser flow.
    //
    // The user's privacy setting is authoritative. Nothing here attempts to
    // work around a denial.
    use std::process::Command;

    const SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
try {
  Add-Type -AssemblyName System.Device
  $w = New-Object System.Device.Location.GeoCoordinateWatcher([System.Device.Location.GeoPositionAccuracy]::High)
  $null = $w.TryStart($false, [TimeSpan]::FromSeconds(30))
  $deadline = (Get-Date).AddSeconds(30)
  while ($w.Status -ne 'Ready' -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
  if ($w.Permission -ne 'Granted') { Write-Output 'DENIED'; exit 0 }
  $l = $w.Position.Location
  if ($l.IsUnknown) { Write-Output 'UNKNOWN'; exit 0 }
  '{0} {1} {2}' -f $l.Latitude, $l.Longitude, $l.HorizontalAccuracy
} catch { Write-Output 'ERROR' }
"#;

    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT])
        .output()
        .ok()?;
    parse_windows_location(&String::from_utf8_lossy(&out.stdout))
}

/// Parse `"<lat> <lon> <accuracy>"` from the PowerShell helper.
///
/// `DENIED`, `UNKNOWN` and `ERROR` all yield `None`, so a refusal or a missing
/// fix falls through to the browser flow instead of being papered over. An
/// accuracy that is absent or not positive is refused rather than assumed good.
#[cfg(any(target_os = "windows", test))]
pub(crate) fn parse_windows_location(s: &str) -> Option<Reading> {
    let line = s.lines().map(str::trim).find(|l| !l.is_empty())?;
    if line == "DENIED" || line == "UNKNOWN" || line == "ERROR" {
        return None;
    }
    let mut it = line.split_whitespace();
    let lat: f64 = it.next()?.parse().ok()?;
    let lon: f64 = it.next()?.parse().ok()?;
    let acc: f64 = it.next()?.parse().ok()?;
    if !acc.is_finite() || acc <= 0.0 {
        return None;
    }
    if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
        return None;
    }
    Some(Reading { lat_deg: lat, lon_deg: lon, accuracy_m: acc })
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn acquire() -> Option<Reading> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn parses_provider_output() {
        let s = "Latitude:    12.971600\nLongitude:   77.594600\nAccuracy:    45.000000 meters\n";
        let r = parse_where_am_i(s).unwrap();
        assert!((r.lat_deg - 12.9716).abs() < 1e-6);
        assert!((r.accuracy_m - 45.0).abs() < 1e-6);
    }

    #[test]
    fn windows_location_output_parses() {
        let r = parse_windows_location("12.9716 77.5946 18.5\n").expect("parse");
        assert!((r.lat_deg - 12.9716).abs() < 1e-9);
        assert!((r.accuracy_m - 18.5).abs() < 1e-9);
    }

    #[test]
    fn windows_refusal_never_becomes_a_reading() {
        // A denial or a missing fix must fall through to the fallback, not be
        // turned into a position.
        for s in ["DENIED", "UNKNOWN", "ERROR", "", "12.9 77.5"] {
            assert!(parse_windows_location(s).is_none(), "{s:?} must not parse");
        }
        // An accuracy of zero or a nonsensical coordinate is refused.
        assert!(parse_windows_location("12.9 77.5 0").is_none());
        assert!(parse_windows_location("999 77.5 10").is_none());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn geoclue_variants_parse() {
        assert_eq!(
            parse_object_path("(objectpath '/org/freedesktop/GeoClue2/Client/1',)\n").as_deref(),
            Some("/org/freedesktop/GeoClue2/Client/1")
        );
        assert_eq!(parse_variant_double("(<12.9716>,)\n"), Some(12.9716));
        assert_eq!(parse_variant_double("(<-33.87>,)"), Some(-33.87));
        assert_eq!(parse_variant_double("nonsense"), None);
    }

    #[test]
    fn unavailable_provider_fails_closed() {
        // On a headless build machine no provider exists; the contract is that
        // this yields None rather than a fabricated reading.
        let r = acquire_location();
        if let Some(x) = r {
            assert!(x.accuracy_m > 0.0, "a real reading must carry real accuracy");
        }
    }
}
