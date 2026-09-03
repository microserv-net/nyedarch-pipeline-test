//! Browser-assisted location acquisition.
//!
//! Native providers are not available everywhere. macOS CoreLocation needs an
//! entitled, bundled application with a run loop; Linux needs a GeoClue agent;
//! headless machines have neither. Rather than give up (or, far worse, accept a
//! typed-in coordinate), NYEDArch can ask the user's browser, which every
//! desktop platform has and which owns a real permission prompt.
//!
//! # How it works
//!
//! 1. A one-shot HTTP listener binds to **127.0.0.1 on an ephemeral port**. It
//!    is never reachable from another machine.
//! 2. A 256-bit random token is generated. Both the page URL and the result
//!    submission must carry it, so another local process cannot post a
//!    location into our listener by guessing the port.
//! 3. The default browser is opened at that URL. The page calls
//!    `navigator.geolocation.getCurrentPosition` with high accuracy requested,
//!    which triggers the browser's own permission prompt.
//! 4. The page posts latitude, longitude and the browser's reported accuracy
//!    back. The listener then shuts down. It answers exactly one request.
//!
//! # What this does and does not prove
//!
//! **It is not a trusted source.** The browser is software on the same machine
//! the user controls; a determined operator can patch it, or drive the page
//! with a spoofed provider. This flow exists so an honest user on a machine
//! without a native provider can still use the location protection. It raises
//! effort; it does not establish trust.
//!
//! **On IP-derived positions.** Browsers may answer a geolocation request from
//! a network-derived estimate rather than GNSS or wifi trilateration. NYEDArch
//! cannot tell which source was used — the API does not say. What it can do,
//! and does, is enforce the accuracy the caller demanded: network and IP
//! estimates report accuracy in the thousands of metres, so they are refused by
//! the existing accuracy gate for any realistic tolerance. A caller asking for
//! 150 m will never be satisfied by an IP-derived fix.
//!
//! The listener also refuses a reading that omits accuracy, rather than
//! treating "unknown" as "good".

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use nyedarch_crypto::geo::Reading;

/// How long to wait for the user to grant permission and the page to answer.
const WAIT: Duration = Duration::from_secs(120);

/// Outcome of a browser acquisition attempt.
#[derive(Debug)]
pub enum BrowserLocationError {
    Listen(String),
    Browser(String),
    TimedOut,
    Denied(String),
    /// A reading arrived without an accuracy figure. Refused rather than
    /// assumed good.
    NoAccuracy,
    Malformed,
}

impl std::fmt::Display for BrowserLocationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BrowserLocationError::Listen(e) => write!(f, "could not open a local listener: {e}"),
            BrowserLocationError::Browser(e) => write!(f, "could not open a browser: {e}"),
            BrowserLocationError::TimedOut => {
                write!(f, "timed out waiting for the browser to report a location")
            }
            BrowserLocationError::Denied(m) => write!(f, "the browser refused: {m}"),
            BrowserLocationError::NoAccuracy => {
                write!(f, "the browser reported a position with no accuracy figure; refused")
            }
            BrowserLocationError::Malformed => write!(f, "the browser sent an unusable response"),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn random_token() -> String {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("csprng");
    hex(&b)
}

/// Open a URL in the platform's default browser.
fn open_browser(url: &str) -> Result<(), BrowserLocationError> {
    #[cfg(target_os = "macos")]
    let (prog, args): (&str, Vec<&str>) = ("open", vec![url]);
    #[cfg(target_os = "windows")]
    let (prog, args): (&str, Vec<&str>) = ("cmd", vec!["/C", "start", "", url]);
    #[cfg(all(unix, not(target_os = "macos")))]
    let (prog, args): (&str, Vec<&str>) = ("xdg-open", vec![url]);

    std::process::Command::new(prog)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|e| BrowserLocationError::Browser(e.to_string()))
}

/// The consent page. It states plainly what is collected before asking.
fn page(token: &str, tolerance_m: Option<u32>) -> String {
    let requirement = match tolerance_m {
        Some(m) => format!(
            "This capsule requires a fix accurate to within {m} metres. \
             A coarse or network-derived position will be refused."
        ),
        None => "A coarse or network-derived position will be refused.".to_string(),
    };
    format!(
        r#"<!doctype html>
<html><head><meta charset="utf-8"><title>NYEDArch location</title>
<style>
 :root {{ color-scheme: dark; }}
 body {{ margin:0; min-height:100vh; display:grid; place-items:center;
        background:#06080f; color:#eaeffa;
        font:15px/1.6 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; }}
 .card {{ width:min(560px,90vw); background:#11162
6; border:1px solid #222b44; border-radius:12px; padding:28px 30px; }}
 h1 {{ margin:0 0 4px; font-size:21px; }}
 .sub {{ color:#93a1c0; margin:0 0 18px; }}
 p {{ color:#93a1c0; }}
 .req {{ background:#0a0d19; border-left:3px solid #38e1ff; padding:12px 14px;
         border-radius:8px; margin:16px 0; color:#eaeffa; }}
 button {{ background:#38e1ff; color:#06080f; border:0; border-radius:9px;
           padding:12px 20px; font-size:15px; font-weight:600; cursor:pointer; }}
 button:disabled {{ background:#2a3350; color:#5c6a8c; cursor:default; }}
 .status {{ margin-top:16px; min-height:22px; }}
 .ok {{ color:#3df0b6; }} .bad {{ color:#ff5c76; }}
 code {{ color:#9b7cff; }}
</style></head>
<body><div class="card">
 <h1>NYEDArch needs your location</h1>
 <p class="sub">Not Your Everyday Archive</p>
 <p>Your browser will ask for permission. If you allow it, this page sends
    <strong>only</strong> latitude, longitude and the reported accuracy back to
    the NYEDArch application running on this computer, over
    <code>127.0.0.1</code>. Nothing leaves this machine.</p>
 <div class="req">{requirement}</div>
 <button id="go">Share my location</button>
 <div class="status" id="s"></div>
 <p style="font-size:12.5px;margin-top:18px">You can close this tab once it says
    the location was received.</p>
</div>
<script>
const S = document.getElementById('s');
document.getElementById('go').onclick = function () {{
  this.disabled = true;
  S.textContent = 'Waiting for permission...';
  if (!navigator.geolocation) {{
    S.className = 'status bad';
    S.textContent = 'This browser has no geolocation support.';
    report({{error: 'unsupported'}});
    return;
  }}
  navigator.geolocation.getCurrentPosition(
    function (pos) {{
      report({{
        lat: pos.coords.latitude,
        lon: pos.coords.longitude,
        acc: pos.coords.accuracy
      }});
      S.className = 'status ok';
      S.textContent = 'Location received. You can close this tab.';
    }},
    function (err) {{
      S.className = 'status bad';
      S.textContent = 'Refused: ' + err.message;
      report({{error: err.message}});
    }},
    {{ enableHighAccuracy: true, timeout: 60000, maximumAge: 0 }}
  );
}};
function report(body) {{
  fetch('/r/{token}', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify(body)
  }}).catch(function () {{}});
}}
</script></body></html>"#
    )
}

/// Pull a JSON number out of a small, known-shape body without a JSON crate.
fn json_number(body: &str, key: &str) -> Option<f64> {
    let pat = format!("\"{key}\"");
    let i = body.find(&pat)? + pat.len();
    let rest = body[i..].trim_start().strip_prefix(':')?.trim_start();
    let end = rest
        .find(|c: char| !(c.is_ascii_digit() || c == '.' || c == '-' || c == '+' || c == 'e' || c == 'E'))
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn json_string<'a>(body: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!("\"{key}\"");
    let i = body.find(&pat)? + pat.len();
    let rest = body[i..].trim_start().strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(&rest[..end])
}

fn respond(mut stream: TcpStream, status: &str, content_type: &str, body: &str) {
    let out = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(out.as_bytes());
    let _ = stream.flush();
}

/// Acquire a location through the user's browser.
///
/// `tolerance_m` is used only to tell the user what will be accepted; the
/// caller still applies the real accuracy check.
pub fn acquire_via_browser(tolerance_m: Option<u32>) -> Result<Reading, BrowserLocationError> {
    // Loopback only. This listener must never be reachable off the machine.
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .map_err(|e| BrowserLocationError::Listen(e.to_string()))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| BrowserLocationError::Listen(e.to_string()))?;
    let port = listener
        .local_addr()
        .map_err(|e| BrowserLocationError::Listen(e.to_string()))?
        .port();

    let token = random_token();
    let url = format!("http://127.0.0.1:{port}/p/{token}");

    // A test hook: when this variable is set, the URL is written there instead
    // of a browser being launched. It exists so the loopback protocol can be
    // exercised automatically. It cannot weaken the flow - it does not accept a
    // location, it only reveals where to send one, and the token still gates it.
    if let Some(path) = std::env::var_os("NYEDARCH_LOCATION_URL_FILE") {
        let _ = std::fs::write(path, &url);
    } else {
        open_browser(&url)?;
    }

    let html = page(&token, tolerance_m);
    let deadline = Instant::now() + WAIT;

    while Instant::now() < deadline {
        match listener.accept() {
            Ok((stream, peer)) => {
                // Defence in depth: refuse anything that is not loopback.
                if !peer.ip().is_loopback() {
                    continue;
                }
                match handle(stream, &token, &html)? {
                    Some(reading) => return Ok(reading),
                    None => continue, // page fetch; keep waiting for the result
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(80));
            }
            Err(e) => return Err(BrowserLocationError::Listen(e.to_string())),
        }
    }
    Err(BrowserLocationError::TimedOut)
}

/// Serve one request. Returns `Some(reading)` when the result arrived.
fn handle(
    stream: TcpStream,
    token: &str,
    html: &str,
) -> Result<Option<Reading>, BrowserLocationError> {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| BrowserLocationError::Listen(e.to_string()))?;
    let mut reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|e| BrowserLocationError::Listen(e.to_string()))?,
    );

    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return Ok(None);
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");

    // Headers, for Content-Length.
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).map_err(|_| BrowserLocationError::Malformed)? == 0 {
            break;
        }
        let l = line.trim_end();
        if l.is_empty() {
            break;
        }
        if let Some(v) = l.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }

    // Serve the consent page.
    if method == "GET" {
        if path == format!("/p/{token}") {
            respond(stream, "200 OK", "text/html; charset=utf-8", html);
        } else {
            // Wrong or missing token: reveal nothing.
            respond(stream, "404 Not Found", "text/plain", "not found");
        }
        return Ok(None);
    }

    // Accept the result.
    if method == "POST" && path == format!("/r/{token}") {
        let mut body = vec![0u8; content_length.min(4096)];
        if reader.read_exact(&mut body).is_err() {
            respond(stream, "400 Bad Request", "text/plain", "bad body");
            return Err(BrowserLocationError::Malformed);
        }
        let body = String::from_utf8_lossy(&body).to_string();

        if let Some(err) = json_string(&body, "error") {
            respond(stream, "200 OK", "text/plain", "ok");
            return Err(BrowserLocationError::Denied(err.to_string()));
        }

        let lat = json_number(&body, "lat");
        let lon = json_number(&body, "lon");
        let acc = json_number(&body, "acc");
        respond(stream, "200 OK", "text/plain", "ok");

        match (lat, lon, acc) {
            (Some(lat), Some(lon), Some(acc)) => {
                // An absent or nonsensical accuracy is refused rather than
                // treated as good.
                if !acc.is_finite() || acc <= 0.0 {
                    return Err(BrowserLocationError::NoAccuracy);
                }
                if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
                    return Err(BrowserLocationError::Malformed);
                }
                return Ok(Some(Reading {
                    lat_deg: lat,
                    lon_deg: lon,
                    accuracy_m: acc,
                }));
            }
            (_, _, None) => return Err(BrowserLocationError::NoAccuracy),
            _ => return Err(BrowserLocationError::Malformed),
        }
    }

    respond(stream, "404 Not Found", "text/plain", "not found");
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_browser_payload() {
        let body = r#"{"lat":12.9716,"lon":77.5946,"acc":18.5}"#;
        assert!((json_number(body, "lat").unwrap() - 12.9716).abs() < 1e-9);
        assert!((json_number(body, "lon").unwrap() - 77.5946).abs() < 1e-9);
        assert!((json_number(body, "acc").unwrap() - 18.5).abs() < 1e-9);
    }

    #[test]
    fn parses_a_refusal() {
        let body = r#"{"error":"User denied Geolocation"}"#;
        assert_eq!(json_string(body, "error"), Some("User denied Geolocation"));
        assert!(json_number(body, "lat").is_none());
    }

    #[test]
    fn negative_and_exponent_forms_parse() {
        let body = r#"{"lat":-33.8688,"lon":1.51e2,"acc":2500}"#;
        assert!((json_number(body, "lat").unwrap() + 33.8688).abs() < 1e-9);
        assert!((json_number(body, "lon").unwrap() - 151.0).abs() < 1e-9);
        assert_eq!(json_number(body, "acc").unwrap(), 2500.0);
    }

    #[test]
    fn tokens_are_unique_and_long() {
        let a = random_token();
        let b = random_token();
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
    }

    #[test]
    fn page_states_the_accuracy_requirement() {
        let p = page("abc", Some(150));
        assert!(p.contains("150 metres"));
        assert!(p.contains("/r/abc"));
        // The page must not promise more than it can deliver.
        assert!(p.contains("refused"));
    }
}
