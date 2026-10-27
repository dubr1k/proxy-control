//! The router's own WARP device for AmneziaWG's `warp` (v3.0.0): a WireGuard key pair, registered
//! once at Cloudflare's client API (the call the 1.1.1.1 app makes) and kept in the router's state
//! directory (`warp-wg.json`, 0600). The host's warp-svc stays what every other service uses; this
//! account exists because warp-svc's SOCKS5 refuses UDP.
//!
//! The key pair comes from the pinned Xray (`xray x25519`, base64url) and is turned into the
//! standard base64 WireGuard and the API use. Nothing here ever logs a key or the token.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde_json::{json, Value};

use crate::https::{self, Failure};
use crate::ipaddr;
use crate::pyjson;
use crate::util::{json_int, py_int, py_truthy};

pub const API: &str = "https://api.cloudflareclient.com/v0a5641";
pub const HEADERS: [(&str, &str); 3] = [
    ("User-Agent", "okhttp/3.12.1"),
    ("CF-Client-Version", "a-6.38.9-5641"),
    ("Content-Type", "application/json; charset=UTF-8"),
];
pub const PORT: u16 = 2408;
pub const TIMEOUT: Duration = Duration::from_secs(20);

/// Registration failed or answered something unusable. Never carries a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarpError(pub String);

impl std::fmt::Display for WarpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// `(method, url, headers, body) -> (status, JSON or None)`.
pub type Opener =
    dyn Fn(&str, &str, &[(&str, &str)], Option<&[u8]>) -> Result<(u16, Option<Value>), WarpError> + Send + Sync;

/// The real API: an HTTP error status comes back as the status with no body.
pub fn urllib_opener(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Result<(u16, Option<Value>), WarpError> {
    let unreachable = |kind: &str| WarpError(format!("WARP API unreachable: {kind}"));
    let parsed = https::parse_url(url).ok_or_else(|| unreachable("ValueError"))?;
    let response = match https::request(&parsed, method, headers, body, TIMEOUT, 65536) {
        Ok(response) => response,
        Err(Failure::Open(_)) => return Err(unreachable("URLError")),
        Err(Failure::Read(text)) if text.contains("timed out") => return Err(unreachable("TimeoutError")),
        Err(Failure::Read(_)) => return Err(unreachable("OSError")),
    };
    if !(200..300).contains(&response.status) {
        return Ok((response.status, None));
    }
    if response.body.is_empty() {
        return Ok((response.status, None));
    }
    let value = serde_json::from_slice(&response.body).map_err(|_| unreachable("JSONDecodeError"))?;
    Ok((response.status, Some(value)))
}

/// `binascii.a2b_base64(data, strict_mode=strict)`: `None` where it raises.
pub fn a2b_base64(data: &[u8], strict: bool) -> Option<Vec<u8>> {
    fn sextet(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    if strict && data.first() == Some(&b'=') {
        return None;
    }
    let (mut out, mut quad, mut left, mut pads, mut padding) = (Vec::new(), 0u8, 0u8, 0u8, false);
    for (i, &c) in data.iter().enumerate() {
        if c == b'=' {
            padding = true;
            if strict && quad == 0 {
                return None;
            }
            if quad >= 2 {
                pads += 1;
                if quad + pads >= 4 {
                    if strict && i + 1 < data.len() {
                        return None;
                    }
                    return Some(out);
                }
            }
            continue;
        }
        let Some(value) = sextet(c) else {
            if strict {
                return None;
            }
            continue;
        };
        if strict && padding {
            return None;
        }
        pads = 0;
        match quad {
            0 => {
                quad = 1;
                left = value;
            }
            1 => {
                quad = 2;
                out.push((left << 2) | (value >> 4));
                left = value & 0x0f;
            }
            2 => {
                quad = 3;
                out.push((left << 4) | (value >> 2));
                left = value & 0x03;
            }
            _ => {
                quad = 0;
                out.push((left << 6) | value);
                left = 0;
            }
        }
    }
    (quad == 0).then_some(out)
}

/// `base64.b64decode(text, validate=True)` of a JSON value.
fn b64decode_strict(value: &Value) -> Option<Vec<u8>> {
    let text = value.as_str().filter(|text| text.is_ascii())?;
    a2b_base64(text.as_bytes(), true)
}

/// A 32-byte key printed as base64url (no padding) as standard base64.
pub fn standard_b64(urlsafe: &str) -> Result<String, WarpError> {
    let invalid = || WarpError("the key pair is not base64url".into());
    if !urlsafe.is_ascii() {
        return Err(invalid());
    }
    let padded = format!("{urlsafe}{}", "=".repeat((4 - urlsafe.len() % 4) % 4));
    let translated: Vec<u8> = padded
        .bytes()
        .map(|b| match b {
            b'-' => b'+',
            b'_' => b'/',
            other => other,
        })
        .collect();
    let raw = a2b_base64(&translated, false).ok_or_else(invalid)?;
    if raw.len() != 32 {
        return Err(WarpError("the key pair is not 32 bytes".into()));
    }
    Ok(base64::engine::general_purpose::STANDARD.encode(raw))
}

/// `IPv4Address(value)`: a dotted string or an integer.
fn ipv4(value: &Value) -> Option<u32> {
    match value {
        Value::String(text) => ipaddr::parse_v4(text),
        Value::Bool(flag) => Some(u32::from(*flag)),
        _ => json_int(value).and_then(|n| u32::try_from(n).ok()),
    }
}

/// `str(value)` of a scalar.
fn py_str(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        other => pc_common::json::dumps(other, &pyjson::DEFAULT),
    }
}

/// `datetime.now(timezone.utc).isoformat(timespec="milliseconds")` with `Z`.
fn tos_now() -> String {
    let since = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let base = crate::util::iso_utc(since.as_secs() as f64);
    format!("{}.{:03}Z", base.trim_end_matches('Z'), since.subsec_millis())
}

/// A new WARP device for the (private, public) base64url pair: the stored account or `WarpError`.
pub fn register(keypair: &(String, String), opener: &Opener) -> Result<Value, WarpError> {
    let private = standard_b64(&keypair.0)?;
    let public = standard_b64(&keypair.1)?;
    let tos = tos_now();
    let body = json!({"key": public, "install_id": "", "fcm_token": "", "tos": tos, "model": "PC", "serial_number": "",
                      "locale": "en_US"});
    let body = pc_common::json::dumps(&body, &pyjson::DEFAULT);
    let (status, data) = opener("POST", &format!("{API}/reg"), &HEADERS, Some(body.as_bytes()))?;
    let data = match data {
        Some(Value::Object(data)) if status == 200 => data,
        _ => return Err(WarpError(format!("WARP registration refused (HTTP {status})"))),
    };
    let shape = || WarpError("WARP registration answered an unexpected shape".into());
    let config = data.get("config").ok_or_else(shape)?;
    let peer = config.get("peers").and_then(|peers| peers.get(0)).ok_or_else(shape)?;
    let address = config.get("interface").and_then(|i| i.get("addresses")).and_then(|a| a.get("v4")).and_then(ipv4);
    let address = ipaddr::format_v4(address.ok_or_else(shape)?);
    let endpoint = peer.get("endpoint").and_then(|e| e.get("v4")).and_then(Value::as_str).ok_or_else(shape)?;
    let host = endpoint.rsplit_once(':').map_or(endpoint, |(host, _)| host);
    let endpoint = ipaddr::format_v4(ipaddr::parse_v4(host).ok_or_else(shape)?);
    let peer_key = peer.get("public_key").ok_or_else(shape)?;
    if b64decode_strict(peer_key).map(|key| key.len()) != Some(32) {
        return Err(shape());
    }
    let device_id = py_str(data.get("id").ok_or_else(shape)?);
    let token = py_str(data.get("token").ok_or_else(shape)?);
    if device_id.is_empty() || token.is_empty() {
        return Err(shape());
    }
    Ok(json!({"id": device_id, "token": token, "private_key": private, "address": address, "peer_public_key": peer_key,
              "endpoint": format!("{endpoint}:{PORT}"), "registered_at": tos}))
}

pub fn valid_account(account: &Value) -> bool {
    let Value::Object(account) = account else { return false };
    for key in ["private_key", "peer_public_key"] {
        if account.get(key).and_then(b64decode_strict).map(|key| key.len()) != Some(32) {
            return false;
        }
    }
    if account.get("address").and_then(ipv4).is_none() {
        return false;
    }
    let Some(endpoint) = account.get("endpoint").and_then(Value::as_str) else { return false };
    let (host, port) = endpoint.rsplit_once(':').unwrap_or(("", endpoint));
    if ipaddr::parse_v4(host).is_none() {
        return false;
    }
    let port_ok = py_int(port, 10).is_some_and(|port| 0 < port && port < 65536);
    port_ok && account.get("id").is_some_and(py_truthy) && account.get("token").is_some_and(py_truthy)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn peer() -> String {
        format!("{}=", "A".repeat(43))
    }

    pub fn registrar(calls: std::sync::Arc<std::sync::Mutex<Vec<String>>>) -> Box<Opener> {
        Box::new(move |method, _url, _headers, _body| {
            calls.lock().unwrap().push(method.to_string());
            Ok((
                200,
                Some(json!({"id": "d1", "token": "t1", "account": {"account_type": "free"}, "config": {
                "interface": {"addresses": {"v4": "172.16.0.2"}},
                "peers": [{"public_key": peer(), "endpoint": {"v4": "162.159.192.5:0"}}]}})),
            ))
        })
    }

    #[test]
    fn registration_turns_the_xray_key_pair_into_standard_base64() {
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let opener = registrar(calls.clone());
        let pair = (format!("kPrivate_{}", "k".repeat(34)), format!("Public_{}", "p".repeat(36)));
        let account = register(&pair, opener.as_ref()).unwrap();
        assert!(valid_account(&account));
        assert_eq!(account["endpoint"], "162.159.192.5:2408");
        assert!(account["registered_at"].as_str().unwrap().ends_with('Z'));
        assert!(register(&("short".into(), "short".into()), opener.as_ref()).is_err());
        let partial: Box<Opener> = Box::new(|_, _, _, _| Ok((200, Some(json!({"id": "x"})))));
        assert!(register(&pair, partial.as_ref()).is_err());
        assert_eq!(*calls.lock().unwrap(), ["POST"]);
    }

    const GOLDEN: &str = include_str!("../testdata/pyjson.json");

    #[test]
    fn base64_and_accounts_follow_the_python_decoders() {
        let golden: Value = serde_json::from_str(GOLDEN).unwrap();
        let standard = base64::engine::general_purpose::STANDARD;
        for entry in golden["base64"].as_array().unwrap() {
            let text = entry["text"].as_str().unwrap();
            match (standard_b64(text), entry.get("urlsafe")) {
                (Ok(out), Some(expected)) => assert_eq!(out, expected.as_str().unwrap(), "{text}"),
                (Err(err), None) => assert_eq!(err.0, entry["urlsafe_error"].as_str().unwrap(), "{text}"),
                (other, _) => panic!("{text}: {other:?}"),
            }
            let strict = b64decode_strict(&json!(text)).map(|raw| standard.encode(raw));
            assert_eq!(strict.as_deref(), entry.get("strict").and_then(Value::as_str), "strict {text}");
        }
        for entry in golden["accounts"].as_array().unwrap() {
            let expected = entry.get("valid").and_then(Value::as_bool).unwrap_or(false);
            assert_eq!(valid_account(&entry["account"]), expected, "{}", entry["account"]);
        }
    }
}
