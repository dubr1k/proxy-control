//! Golden vectors recorded from Python (`fixtures/record_goldens.py`): `json.loads` on request
//! bodies, `mimetypes.guess_type`, `formatdate`/etag of `FileResponse`, the subscription CSP.

use base64::Engine as _;
use panel_web::http::json_loads::{loads, LoadsError};
use panel_web::http::static_files::{etag, formatdate, guess_type};
use serde_json::Value;

fn fixture(name: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name);
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[test]
fn json_loads_matches_python() {
    let mut failures = Vec::new();
    for case in fixture("json_corpus.json").as_array().unwrap() {
        let input = base64::engine::general_purpose::STANDARD.decode(case["input"].as_str().unwrap()).unwrap();
        let got = loads(&input);
        let ok = if let Some(error) = case.get("error") {
            got == Err(LoadsError::Decode {
                msg: error["msg"].as_str().unwrap().to_string(),
                pos: error["pos"].as_u64().unwrap() as usize,
            })
        } else if case.get("other_error").is_some() {
            matches!(got, Err(LoadsError::Other(_)))
        } else if case.get("value_not_json").is_some() || case.get("lone_surrogate").is_some() {
            matches!(got, Err(LoadsError::Unrepresentable { .. }))
        } else {
            got.as_ref().map(panel_core::pyjson::dumps_default).ok().as_deref() == case["value"].as_str()
        };
        if !ok {
            failures.push(format!("{:?}: python {case}, rust {got:?}", String::from_utf8_lossy(&input)));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn mimetypes_match_the_image() {
    let constants = fixture("python_constants.json");
    for (name, expected) in constants["guesses"].as_object().unwrap() {
        assert_eq!(guess_type(&format!("/app/panel/static/{name}")), expected.as_str(), "{name}");
    }
}

#[test]
fn file_response_stat_headers_match_python() {
    for vector in fixture("python_constants.json")["file_vectors"].as_array().unwrap() {
        let mtime = vector["mtime"].as_f64().unwrap();
        let text = panel_core::pyjson::float_repr(mtime);
        assert_eq!(text, vector["mtime_str"].as_str().unwrap());
        assert_eq!(formatdate(mtime), vector["last_modified"].as_str().unwrap());
        assert_eq!(etag(&text, vector["size"].as_u64().unwrap()), vector["etag"].as_str().unwrap());
    }
}

#[test]
fn subscription_csp_is_pythons() {
    assert_eq!(
        fixture("python_constants.json")["subscription_csp"].as_str().unwrap(),
        panel_web::server::SUBSCRIPTION_CSP
    );
}
