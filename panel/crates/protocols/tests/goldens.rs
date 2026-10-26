//! Every link, config and QR code against the bytes the Python panel produced
//! (`fixtures/goldens.json`, recorded by `fixtures/record_goldens.py` on ams-test).

use std::sync::OnceLock;
use std::time::Duration;

use base64::Engine as _;
use panel_managers::TelemtClient;
use panel_model::clients::AccessGrant;
use panel_model::protocols::AdapterError;
use panel_model::validate::Model;
use panel_protocols::error::runtime_failure;
use panel_protocols::{amneziawg, mieru, naive, reveals, telemt, trusttunnel, trusttunnel_link};
use serde_json::{json, Value};

fn goldens() -> &'static Value {
    static GOLDENS: OnceLock<Value> = OnceLock::new();
    GOLDENS.get_or_init(|| {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/goldens.json");
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    })
}

fn cases(path: &[&str]) -> &'static Vec<Value> {
    let mut value = goldens();
    for key in path {
        value = &value[*key];
    }
    value.as_array().unwrap_or_else(|| panic!("no golden {path:?}"))
}

fn bytes(value: &Value) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(value["$bytes"].as_str().unwrap()).unwrap()
}

fn enc_bytes(value: &[u8]) -> Value {
    json!({"$bytes": base64::engine::general_purpose::STANDARD.encode(value)})
}

/// The golden's error class and message, or its value.
fn expected(case: &Value) -> Result<&Value, (&str, &str)> {
    match case.get("error") {
        Some(class) => Err((class.as_str().unwrap(), case["message"].as_str().unwrap())),
        None => Ok(&case["value"]),
    }
}

/// An adapter's error against Python's: an `AdapterError` by message; anything else Python raised
/// (a crash, a 500) is a crash here too.
fn check_adapter_error(case: &Value, error: &AdapterError) {
    let (class, message) = expected(case).unwrap_err();
    if case["adapter_error"] == json!(true) {
        assert_eq!(error.message, message, "{case}");
        assert!(runtime_failure(error).is_none(), "{case}");
    } else {
        assert_eq!(runtime_failure(error).map(|failure| failure.status), Some(500), "Python raised {class}: {case}");
    }
}

fn artifacts_value(artifacts: &[panel_model::protocols::AccessArtifact]) -> Value {
    artifacts
        .iter()
        .map(|item| {
            json!({"kind": item.kind, "label": item.label, "media_type": item.media_type, "value": item.value,
                   "auto_refresh": item.auto_refresh.as_str()})
        })
        .collect()
}

fn check_render(case: &Value, rendered: Result<Vec<panel_model::protocols::AccessArtifact>, AdapterError>) {
    match (expected(case), rendered) {
        (Ok(value), Ok(artifacts)) => assert_eq!(&artifacts_value(&artifacts), value, "{}", case["grant"]),
        (Err(_), Err(error)) => check_adapter_error(case, &error),
        (Ok(value), Err(error)) => panic!("Python rendered {value}, Rust failed: {error:?} for {}", case["grant"]),
        (Err(error), Ok(artifacts)) => panic!("Python failed {error:?}, Rust rendered {artifacts:?}"),
    }
}

fn grant(case: &Value) -> AccessGrant {
    AccessGrant::validate(&case["grant"]).unwrap()
}

// ---- tt:// ----------------------------------------------------------------------------------------

#[test]
fn deeplinks_are_encoded_byte_for_byte() {
    for case in cases(&["deeplink", "encode"]) {
        let input = &case["input"];
        let text = |key: &str| input[key].as_str().unwrap_or_default().to_string();
        let mut spec = trusttunnel_link::DeepLinkSpec::new(
            &text("hostname"),
            input["addresses"].as_array().unwrap().iter().map(|a| a.as_str().unwrap().to_string()).collect(),
            &text("username"),
            &text("password"),
        );
        spec.name = input["name"].as_str().map(str::to_string);
        spec.certificate_der = input.get("certificate_der").map(bytes);
        spec.skip_verification = input["skip_verification"] == json!(true);
        if let Some(protocol) = input["upstream_protocol"].as_u64() {
            spec.upstream_protocol = protocol;
        }
        let encoded = trusttunnel_link::encode_deeplink(&spec);
        match expected(case) {
            Ok(value) => assert_eq!(&json!(encoded.unwrap()), value),
            Err((_, message)) => assert_eq!(encoded.unwrap_err().0, message),
        }
    }
}

#[test]
fn deeplinks_are_decoded_like_python() {
    for case in cases(&["deeplink", "decode"]) {
        let decoded = trusttunnel_link::decode_deeplink(case["input"].as_str().unwrap());
        match expected(case) {
            Ok(value) => {
                let mut decoded = decoded.unwrap_or_else(|error| panic!("{}: {error}", case["input"])).to_value();
                if let Some(certificate) = decoded.get_mut("certificate") {
                    let raw = base64::engine::general_purpose::STANDARD.decode(certificate.as_str().unwrap()).unwrap();
                    *certificate = enc_bytes(&raw);
                }
                assert_eq!(&decoded, value, "{}", case["input"]);
            }
            Err((_, message)) => assert_eq!(decoded.unwrap_err().0, message, "{}", case["input"]),
        }
    }
}

#[test]
fn varints_match_python() {
    for case in cases(&["deeplink", "encode_varint"]) {
        let encoded = trusttunnel_link::encode_varint(i128::from(case["input"].as_i64().unwrap()));
        match expected(case) {
            Ok(value) => assert_eq!(&enc_bytes(&encoded.unwrap()), value),
            Err((_, message)) => assert_eq!(encoded.unwrap_err().0, message),
        }
    }
    for case in cases(&["deeplink", "decode_varint"]) {
        let decoded =
            trusttunnel_link::decode_varint(&bytes(&case["input"]), case["offset"].as_u64().unwrap() as usize);
        match expected(case) {
            Ok(value) => {
                let (number, offset) = decoded.unwrap();
                assert_eq!(&json!([number, offset]), value);
            }
            Err((_, message)) => assert_eq!(decoded.unwrap_err().0, message),
        }
    }
}

// ---- TrustTunnel ---------------------------------------------------------------------------------

#[test]
fn trusttunnel_credentials_ders_pems_and_toml_strings_match_python() {
    for case in cases(&["trusttunnel", "parse_credential"]) {
        match (expected(case), trusttunnel::parse_credential(&bytes(&case["input"]))) {
            (Ok(value), Ok(password)) => assert_eq!(&json!(password), value),
            (Err(_), Err(error)) => check_adapter_error(case, &error),
            (want, got) => panic!("{}: Python {want:?}, Rust {got:?}", case["input"]),
        }
    }
    for case in cases(&["trusttunnel", "split_der"]) {
        let input = bytes(&case["input"]);
        match (expected(case), trusttunnel::split_der(&input)) {
            (Ok(value), Ok(parts)) => assert_eq!(&parts.iter().map(|der| enc_bytes(der)).collect::<Value>(), value),
            (Err(_), Err(error)) => check_adapter_error(case, &error),
            (want, got) => panic!("{}: Python {want:?}, Rust {got:?}", case["input"]),
        }
    }
    for case in cases(&["trusttunnel", "certificate_pem"]) {
        match (expected(case), trusttunnel::certificate_pem(case["input"].as_str().unwrap())) {
            (Ok(value), Ok(pem)) => assert_eq!(&json!(pem), value),
            (Err(_), Err(error)) => check_adapter_error(case, &error),
            (want, got) => panic!("{}: Python {want:?}, Rust {got:?}", case["input"]),
        }
    }
    for case in cases(&["trusttunnel", "toml_string"]) {
        assert_eq!(json!(trusttunnel::toml_string(case["input"].as_str().unwrap())), case["value"]);
    }
    for case in cases(&["trusttunnel", "learned_options"]) {
        let learned = trusttunnel::learned_options(case["input"].as_object().unwrap());
        assert_eq!(Value::Object(learned), case["value"], "{}", case["input"]);
    }
}

#[test]
fn trusttunnel_links_toml_and_manual_fields_are_byte_exact() {
    let adapter: panel_protocols::TrusttunnelAdapter = panel_protocols::TrusttunnelAdapter::new(
        panel_managers::TrusttunnelClient::new("/nonexistent", "x"),
        "fallback.example.com",
    );
    for case in cases(&["trusttunnel", "render"]) {
        let rendered =
            adapter.render_artifacts(&grant(case), &bytes(&case["credential"]), case["public_host"].as_str().unwrap());
        check_render(case, rendered);
    }
}

// ---- AmneziaWG ------------------------------------------------------------------------------------

#[test]
fn amneziawg_public_keys_match_python() {
    for case in cases(&["amneziawg", "public_key_of"]) {
        assert_eq!(json!(amneziawg::public_key_of(case["input"].as_str().unwrap()).unwrap()), case["value"]);
    }
}

#[test]
fn amneziawg_credentials_and_learned_options_match_python() {
    for case in cases(&["amneziawg", "parse_credential"]) {
        match (expected(case), amneziawg::parse_credential(&bytes(&case["input"]))) {
            (Ok(value), Ok((private, preshared))) => assert_eq!(&json!([private, preshared]), value),
            (Err(_), Err(error)) => check_adapter_error(case, &error),
            (want, got) => panic!("{}: Python {want:?}, Rust {got:?}", case["input"]),
        }
    }
    for case in cases(&["amneziawg", "learned_options"]) {
        let input = &case["input"];
        let learned =
            amneziawg::learned_options(input["peer"].as_object().unwrap(), input["instance"].as_object().unwrap());
        match (expected(case), learned) {
            (Ok(value), Ok(learned)) => assert_eq!(&Value::Object(learned), value),
            (Err(_), Err(error)) => check_adapter_error(case, &error),
            (want, got) => panic!("{input}: Python {want:?}, Rust {got:?}"),
        }
    }
}

#[test]
fn amneziawg_configs_are_byte_exact() {
    let adapter: panel_protocols::AmneziawgAdapter =
        panel_protocols::AmneziawgAdapter::new(panel_managers::AmneziawgClient::new("/nonexistent", "x"), "");
    for case in cases(&["amneziawg", "render"]) {
        let rendered =
            adapter.render_artifacts(&grant(case), &bytes(&case["credential"]), case["public_host"].as_str().unwrap());
        check_render(case, rendered);
    }
}

// ---- NaiveProxy, Mieru, Telemt ---------------------------------------------------------------------

#[test]
fn naive_proxy_urls_are_byte_exact() {
    let adapter: panel_protocols::NaiveAdapter =
        panel_protocols::NaiveAdapter::new(panel_managers::NaiveClient::new("/nonexistent", "x"), "naive.example.com");
    for case in cases(&["naive"]) {
        if let Some(input) = case["input"].as_array() {
            let text = |index: usize| input[index].as_str().unwrap();
            assert_eq!(json!(naive::proxy_url(text(0), text(1), text(2))), case["value"]);
            continue;
        }
        let rendered =
            adapter.render_artifacts(&grant(case), &bytes(&case["credential"]), case["public_host"].as_str().unwrap());
        check_render(case, rendered);
    }
}

#[test]
fn mieru_share_urls_templates_and_artifacts_are_byte_exact() {
    for case in cases(&["mieru", "share_url"]) {
        let input = case["input"].as_array().unwrap();
        let text = |index: usize| input[index].as_str().unwrap();
        assert_eq!(json!(mieru::share_url(text(0), text(1), text(2), input[3].as_i64().unwrap())), case["value"]);
    }
    for case in cases(&["mieru", "template_from"]) {
        let input = case["input"].as_array().unwrap();
        let text = |index: usize| input[index].as_str().unwrap();
        assert_eq!(json!(mieru::template_from(&input[0], text(1), text(2))), case["value"], "{input:?}");
    }
    let adapter: panel_protocols::MieruAdapter =
        panel_protocols::MieruAdapter::new(panel_managers::MieruClient::new("/nonexistent", "x"), "mieru.example.com");
    for case in cases(&["mieru", "render"]) {
        let rendered =
            adapter.render_artifacts(&grant(case), &bytes(&case["credential"]), case["public_host"].as_str().unwrap());
        check_render(case, rendered);
    }
    for case in cases(&["mieru", "share"]) {
        let input = case["input"].as_array().unwrap();
        assert_eq!(json!(adapter.share(input[0].as_str().unwrap(), input[1].as_str().unwrap())), case["value"]);
    }
}

#[test]
fn mieru_share_urls_are_parsed_strictly_like_python() {
    for case in cases(&["mieru", "parse_share_url"]) {
        let Some(input) = case["input"].as_str() else { continue }; // a non-string is not a `&str` here
        match (expected(case), mieru::parse_share_url(input)) {
            (Ok(value), Ok(share)) => {
                let singbox = mieru::singbox_outbounds(&share, |port, protocol| format!("mieru-{protocol}-{port}"));
                let parsed = json!({"username": share.username, "password": share.password, "host": share.host,
                                    "is_ip": share.is_ip, "profile": share.profile, "bindings": share.bindings,
                                    "mtu": share.mtu, "exact_ports": share.exact_ports(), "singbox": singbox});
                assert_eq!(&parsed, value, "{input}");
            }
            (Err((_, message)), Err(error)) => assert_eq!(error.0, message, "{input}"),
            (want, got) => panic!("{input}: Python {want:?}, Rust {got:?}"),
        }
    }
}

#[test]
fn telemt_links_documents_and_revisions_match_python() {
    for case in cases(&["telemt", "link"]) {
        let input = case["input"].as_array().unwrap();
        let link = telemt::link(input[0].as_str().unwrap(), &input[1].to_string(), input[2].as_str().unwrap());
        assert_eq!(json!(link), case["value"]);
    }
    type Adapter = panel_protocols::TelemtAdapter<TelemtClient, panel_managers::XrayRouterClient>;
    let adapter: Adapter = panel_protocols::TelemtAdapter::new(TelemtClient::new("http://127.0.0.1:9", "x"))
        .with_public_host("fallback.example.com")
        .with_public_port(8443);
    for case in cases(&["telemt", "render"]) {
        let rendered =
            adapter.render_artifacts(&grant(case), &bytes(&case["credential"]), case["public_host"].as_str().unwrap());
        check_render(case, rendered);
    }
    for case in cases(&["telemt", "document_of"]) {
        let upstreams: Vec<_> =
            case["input"].as_array().unwrap().iter().map(|item| item.as_object().unwrap().clone()).collect();
        assert_eq!(json!(Adapter::document_of(&upstreams)), case["document"], "{}", case["input"]);
        assert_eq!(json!(Adapter::revision_of(&upstreams)), case["revision"], "{}", case["input"]);
    }
    for case in cases(&["telemt", "probe_invalid"]) {
        assert_eq!(json!(telemt::probe_bridge(&case["input"], Duration::from_millis(10))), case["value"]);
    }
}

// ---- QR codes and Karing ----------------------------------------------------------------------------

/// The QR payload of a Python data URI, read back from its SVG path: the module matrix.
fn modules_of(data_uri: &str) -> Vec<(usize, usize)> {
    let svg = base64::engine::general_purpose::STANDARD
        .decode(data_uri.strip_prefix("data:image/svg+xml;base64,").unwrap())
        .unwrap();
    let svg = String::from_utf8(svg).unwrap();
    let path = svg.split("d=\"").nth(1).unwrap().split('"').next().unwrap();
    path.split('M')
        .filter(|square| !square.is_empty())
        .map(|square| {
            let (x, rest) = square.split_once(',').unwrap();
            let y = rest.split('H').next().unwrap();
            (x.parse().unwrap(), y.parse().unwrap())
        })
        .collect()
}

/// python-qrcode 8.2 reports an overflow from its version setter.
const OVERFLOW: (&str, &str) = ("ValueError", "Invalid version (was 41, expected 1 to 40)");

#[test]
fn qr_codes_are_byte_identical_to_python_qrcode() {
    let mut compared = 0;
    for case in cases(&["qr"]) {
        let payload = case["input"].as_str().unwrap();
        let ours = reveals::qr_data(payload);
        if let Some(digest) = case["sha256"].as_str() {
            // A large code is kept as the digest of Python's data URI.
            let uri = ours.unwrap_or_else(|_| panic!("{} chars overflow here, not in Python", payload.chars().count()));
            let length = case["length"].as_u64().unwrap();
            assert_eq!((panel_core::ids::sha256_hex(&uri).as_str(), uri.len() as u64), (digest, length));
            compared += 1;
            continue;
        }
        match (expected(case), ours) {
            (Ok(value), Ok(uri)) => {
                compared += 1;
                let want = value.as_str().unwrap();
                if uri != want {
                    // Say how far apart they are before failing: the same payload must give the
                    // same modules.
                    let (ours, theirs) = (modules_of(&uri), modules_of(want));
                    panic!(
                        "QR of {} chars differs: {} vs {} dark modules, first difference at {:?}",
                        payload.chars().count(),
                        ours.len(),
                        theirs.len(),
                        ours.iter().zip(&theirs).position(|(a, b)| a != b)
                    );
                }
            }
            (Err(error), Err(reveals::DataOverflow)) => assert_eq!(error, OVERFLOW),
            (want, got) => panic!("{} chars: Python {want:?}, Rust {got:?}", payload.chars().count()),
        }
    }
    assert!(compared >= 15, "only {compared} codes were compared");
}

/// `client_routes._qr_of` catches `ValueError`, which is what python-qrcode raises for a payload
/// over version 40-M: such an artifact has no QR in either panel.
#[test]
fn an_oversized_config_has_no_qr() {
    let overflowing = cases(&["qr"])
        .iter()
        .filter(|case| expected(case) == Err(OVERFLOW))
        .map(|case| case["input"].as_str().unwrap())
        .find(|payload| payload.starts_with("[Interface]"))
        .unwrap();
    assert_eq!(reveals::artifact_qr(amneziawg::CONF_MEDIA_TYPE, overflowing), None);
    assert!(reveals::artifact_qr("text/uri-list", "tt://?AAEB").is_some());
    assert_eq!(reveals::artifact_qr("application/toml", "x"), None);
}

#[test]
fn karing_clients_are_byte_exact() {
    for case in cases(&["karing"]) {
        let input = &case["input"];
        let client = reveals::karing_client(
            &input["config"],
            input["name"].as_str().unwrap(),
            input["filename"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(client, case["value"]);
        assert_eq!(serde_json::to_string(&client).unwrap(), serde_json::to_string(&case["value"]).unwrap());
    }
}
