//! Replays `fixtures/probes.json` against the Rust panel and compares the normalised answers with
//! what the Python panel (uvicorn, the production flags) answered (`fixtures/framework_probes.json`,
//! recorded by `fixtures/record_goldens.py`): 404/405 with `Allow`/307 trailing slash/HEAD, the
//! host check, the body limit, 422 precedence and bodies, security headers, cookies, static files,
//! and the auth/admin/audit/key/readiness/OpenAPI routes.

mod common;

use std::collections::HashMap;

use base64::Engine as _;
use panel_secrets::audit::Actor;
use serde_json::{json, Value};
use sha2::Digest as _;

/// Deliberate differences (DIFFERENCES.md): the probe and what Rust answers instead.
fn known_difference(name: &str) -> Option<Value> {
    match name {
        // Python accepted `NaN`, then failed rendering (500); Rust refuses the body as not JSON.
        "keys_nan_session" => Some(json!({
            "status": 422,
            "body": r#"{"detail":[{"type":"json_invalid","loc":["body",41],"msg":"JSON decode error","input":{},"ctx":{"error":"NaN is not accepted"}}]}"#,
        })),
        _ => None,
    }
}

const VOLATILE_JSON_KEYS: [&str; 4] = ["created_at", "plaintext", "prefix", "last_used_at"];

/// `mask_json` of the recorder: `"key":<int|"string"|null>` → `"key":"<masked>"`.
fn mask_json(text: &str) -> String {
    let mut out = text.to_string();
    for key in VOLATILE_JSON_KEYS {
        let needle = format!("\"{key}\":");
        let mut result = String::new();
        let mut rest = out.as_str();
        while let Some(at) = rest.find(&needle) {
            result.push_str(&rest[..at + needle.len()]);
            let value = &rest[at + needle.len()..];
            let length = if let Some(stripped) = value.strip_prefix('"') {
                stripped.find('"').map(|end| end + 2)
            } else if value.starts_with("null") {
                Some(4)
            } else {
                let digits = value.chars().take_while(|ch| ch.is_ascii_digit() || *ch == '-').count();
                (digits > 0).then_some(digits)
            };
            match length {
                Some(length) => {
                    result.push_str("\"<masked>\"");
                    rest = &value[length..];
                }
                None => rest = value,
            }
        }
        result.push_str(rest);
        out = result;
    }
    out
}

fn normalise(status: u16, headers: &[(String, String)], body: &[u8]) -> Value {
    let mut boundary = None;
    let mut shown: Vec<(String, String)> = Vec::new();
    for (name, value) in headers {
        if matches!(name.as_str(), "date" | "server" | "connection") {
            continue;
        }
        let value = match name.as_str() {
            "x-request-id" => {
                if value.len() == 16 && value.chars().all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()) {
                    "<request-id>".to_string()
                } else {
                    format!("<bad:{value}>")
                }
            }
            "set-cookie" => {
                let mut value = value.clone();
                for name in ["panel_session", "panel_csrf"] {
                    let prefix = format!("{name}=");
                    if value.starts_with(&prefix) {
                        let token: String = value[prefix.len()..]
                            .chars()
                            .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '-')
                            .collect();
                        if token.len() == 43 {
                            value = format!("{prefix}<token>{}", &value[prefix.len() + 43..]);
                        }
                    }
                }
                value
            }
            "etag" | "last-modified" => format!("<{name}>"),
            "content-type" if value.contains("boundary=") => {
                let found = value.split_once("boundary=").unwrap().1.to_string();
                let replaced = value.replace(&found, "<boundary>");
                boundary = Some(found);
                replaced
            }
            _ => value.clone(),
        };
        shown.push((name.clone(), value));
    }
    shown.sort();
    let mut body = body.to_vec();
    if let Some(boundary) = boundary {
        body = String::from_utf8_lossy(&body).replace(&boundary, "<boundary>").into_bytes();
    }
    if shown.iter().any(|(name, value)| name == "content-type" && value == "application/json") {
        body = mask_json(&String::from_utf8_lossy(&body)).into_bytes();
    }
    let mut out = json!({"status": status, "headers": shown.iter().map(|(n, v)| json!([n, v])).collect::<Vec<_>>()});
    match String::from_utf8(body.clone()) {
        Ok(text) if body.len() <= 4096 => {
            out["body"] = Value::String(text);
        }
        _ => {
            out["body_sha256"] = Value::String(panel_core::ids::hex(&sha2::Sha256::digest(&body)));
            out["body_length"] = json!(body.len());
        }
    }
    out
}

fn render(text: &str, context: &HashMap<String, String>) -> String {
    let mut text = text.to_string();
    for (name, value) in context {
        text = text.replace(&format!("{{{name}}}"), value);
    }
    text
}

fn cookie_token(headers: &[(String, String)], name: &str) -> String {
    headers
        .iter()
        .filter(|(key, _)| key == "set-cookie")
        .find_map(|(_, value)| {
            value.strip_prefix(&format!("{name}=")).map(|rest| rest.split(';').next().unwrap().to_string())
        })
        .unwrap()
}

#[test]
fn framework_probes_match_python() {
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let probes: Value = serde_json::from_slice(&std::fs::read(fixtures.join("probes.json")).unwrap()).unwrap();
    let expected: Vec<Value> =
        serde_json::from_slice(&std::fs::read(fixtures.join("framework_probes.json")).unwrap()).unwrap();
    let hosts = probes["allowed_hosts"].as_str().unwrap();
    let panel = common::start(&[("PANEL_ALLOWED_HOSTS", hosts)]);
    panel.state.store.create_admin("owner", "correct horse battery staple", "owner").unwrap();
    let mut context = HashMap::new();
    for scope in ["admin", "monitor", "node-sync"] {
        let (_, plaintext) = panel
            .state
            .api_keys
            .create(&format!("probe-{scope}"), scope, None, &Actor::new(None, "installer"), "127.0.0.1", None)
            .unwrap();
        context.insert(format!("key_{}", scope.replace('-', "_")), plaintext);
    }
    let page = common::exchange(&panel.socket, b"GET /login HTTP/1.1\r\nHost: testserver\r\nConnection: close\r\n\r\n");
    let (_, headers, _) = common::parse(&page, false);
    let csrf = cookie_token(&headers, "panel_csrf");
    let body = r#"{"username": "owner", "password": "correct horse battery staple"}"#;
    let login = format!(
        "POST /api/auth/login HTTP/1.1\r\nHost: testserver\r\nContent-Type: application/json\r\nX-CSRF-Token: {csrf}\r\nCookie: panel_csrf={csrf}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let (status, headers, _) = common::parse(&common::exchange(&panel.socket, login.as_bytes()), false);
    assert_eq!(status, 204);
    context.insert("session".into(), cookie_token(&headers, "panel_session"));
    context.insert("csrf".into(), cookie_token(&headers, "panel_csrf"));
    let (_, headers, _) = common::parse(
        &common::exchange(
            &panel.socket,
            b"GET /static/app.js HTTP/1.1\r\nHost: testserver\r\nConnection: close\r\n\r\n",
        ),
        false,
    );
    context.insert("etag_app_js".into(), common::header(&headers, "etag").unwrap().to_string());
    context.insert("last_modified_app_js".into(), common::header(&headers, "last-modified").unwrap().to_string());

    let mut failures = Vec::new();
    for (probe, want) in probes["probes"].as_array().unwrap().iter().zip(&expected) {
        let name = probe["name"].as_str().unwrap();
        assert_eq!(want["name"], name);
        let request = render(probe["request"].as_str().unwrap(), &context);
        let mut raw: Vec<u8> = request.chars().map(|ch| ch as u8).collect();
        if let Some(body) = probe["body"].as_str() {
            raw.extend_from_slice(body.as_bytes());
        } else if let Some(body) = probe["body_b64"].as_str() {
            raw.extend_from_slice(&base64::engine::general_purpose::STANDARD.decode(body).unwrap());
        }
        let (status, headers, body) =
            common::parse(&common::exchange(&panel.socket, &raw), request.starts_with("HEAD "));
        let got = normalise(status, &headers, &body);
        let mut want = want.clone();
        want.as_object_mut().unwrap().remove("name");
        if let Some(difference) = known_difference(name) {
            if got["status"] != difference["status"] || got["body"] != difference["body"] {
                failures.push(format!("{name} (known difference): got {got}"));
            }
            continue;
        }
        if got != want {
            failures.push(format!("{name}:\n  python: {want}\n  rust:   {got}"));
        }
    }
    assert!(failures.is_empty(), "{} of {} probes differ:\n{}", failures.len(), expected.len(), failures.join("\n"));
}
