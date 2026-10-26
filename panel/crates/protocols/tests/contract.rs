//! The Python unit tests of the slice that need no client: the adapter contract's declared
//! differences, and the link, config and credential rules (`test_protocol_adapter_contract.py`,
//! `test_trusttunnel.py`, `test_amneziawg.py`). The certificates are the generated ones of the
//! golden file.

use std::sync::{Arc, OnceLock};

use base64::Engine as _;
use panel_managers::{AmneziawgClient, MieruClient, NaiveClient, TelemtClient, TrusttunnelClient, XrayRouterClient};
use panel_model::clients::{
    AccessGrant, AmneziawgOptions, GrantDesiredState, GrantObservedState, GrantOrigin, ProtocolOptions,
    TrusttunnelOptions,
};
use panel_model::fleet::CredentialOrigin;
use panel_model::protocols::ProtocolAdapter;
use panel_model::Protocol;
use panel_protocols::trusttunnel_link::{decode_deeplink, encode_deeplink, encode_varint, DeepLinkSpec};
use panel_protocols::{amneziawg, trusttunnel};
use panel_protocols::{AmneziawgAdapter, MieruAdapter, NaiveAdapter, TelemtAdapter, TrusttunnelAdapter};
use serde_json::Value;

fn certificates() -> &'static (Vec<u8>, Vec<u8>) {
    static CERTIFICATES: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    CERTIFICATES.get_or_init(|| {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/goldens.json");
        let goldens: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let engine = base64::engine::general_purpose::STANDARD;
        let pems: Vec<Vec<u8>> = goldens["trusttunnel"]["split_der"][1]["value"]
            .as_array()
            .unwrap()
            .iter()
            .map(|der| engine.decode(der["$bytes"].as_str().unwrap()).unwrap())
            .collect();
        (pems[0].clone(), pems[1].clone())
    })
}

fn grant(protocol: Protocol, options: ProtocolOptions, username: &str) -> AccessGrant {
    AccessGrant {
        protocol,
        options,
        id: "g1".into(),
        client_id: "c1".into(),
        node_id: "local".into(),
        endpoint_id: "default".into(),
        runtime_username: username.into(),
        secret_ref: None,
        desired_state: GrantDesiredState::Enabled,
        observed_state: GrantObservedState::Unknown,
        valid_from: None,
        valid_until: None,
        origin: GrantOrigin::Provisioned,
        own_lane: false,
        label: None,
        created_at: 1,
        updated_at: 1,
    }
}

#[test]
fn every_adapter_declares_caller_credential_support_and_update_options() {
    let adapters: Vec<Arc<dyn ProtocolAdapter>> = vec![
        Arc::new(TelemtAdapter::<TelemtClient, XrayRouterClient>::new(TelemtClient::new("http://127.0.0.1:9", "x"))),
        Arc::new(NaiveAdapter::new(NaiveClient::new("/x", "t"), "naive.example.com")),
        Arc::new(MieruAdapter::new(MieruClient::new("/x", "t"), "")),
        Arc::new(AmneziawgAdapter::new(AmneziawgClient::new("/x", "t"), "")),
        Arc::new(TrusttunnelAdapter::<TrusttunnelClient, XrayRouterClient>::new(TrusttunnelClient::new("/x", "t"), "")),
    ];
    let declared: Vec<_> = adapters
        .iter()
        .map(|adapter| {
            (
                adapter.protocol(),
                adapter.credential_origin(),
                adapter.capture_supported(),
                adapter.accepts_caller_credential(),
            )
        })
        .collect();
    assert_eq!(
        declared,
        vec![
            // Telemt generates the secret itself (and now also takes a caller's); the live link carries it.
            (Protocol::Mtproxy, CredentialOrigin::Manager, true, true),
            (Protocol::Naive, CredentialOrigin::Caller, true, true),
            // mita keeps a hash: saying "no" is the honest answer.
            (Protocol::Mieru, CredentialOrigin::Caller, false, true),
            (Protocol::Amneziawg, CredentialOrigin::Caller, false, true),
            (Protocol::Trusttunnel, CredentialOrigin::Caller, false, true),
        ]
    );
}

#[test]
fn the_panel_writes_a_link_the_stable_official_client_reads() {
    let spec = DeepLinkSpec {
        name: Some("n".into()),
        certificate_der: Some(certificates().0.clone()),
        skip_verification: true,
        ..DeepLinkSpec::new("h", vec!["a:1".into()], "u", "secret-1")
    };
    let link = encode_deeplink(&spec).unwrap();
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&link["tt://?".len()..]).unwrap();
    assert_eq!(&payload[..3], b"\x00\x01\x01");
    assert_eq!(decode_deeplink(&link).unwrap().version, 1);
}

#[test]
fn a_link_round_trips_with_a_certificate_a_name_and_unicode() {
    let (first, second) = certificates();
    let chain = [first.as_slice(), second].concat();
    let spec = DeepLinkSpec {
        name: Some("Алиса · телефон".into()),
        certificate_der: Some(chain.clone()),
        skip_verification: true,
        ..DeepLinkSpec::new(
            "gate.example.com",
            vec!["gate.example.com:443".into(), "[2001:db8::1]:443".into()],
            "alice-1.x_y",
            &"Zz9-_".repeat(8),
        )
    };
    let link = encode_deeplink(&spec).unwrap();
    assert!(link.starts_with("tt://?") && !link["tt://?".len()..].contains(['=', '+', '/']));
    let decoded = decode_deeplink(&link).unwrap();
    assert_eq!(decoded.addresses, ["gate.example.com:443", "[2001:db8::1]:443"]);
    assert_eq!(decoded.certificate.as_deref(), Some(chain.as_slice()));
    assert_eq!(decoded.name.as_deref(), Some("Алиса · телефон"));
    assert_eq!(decoded.username.as_deref(), Some("alice-1.x_y"));
    assert_eq!(decoded.password, Some("Zz9-_".repeat(8)));
    assert!(decoded.skip_verification && decoded.upstream_protocol == 1);
}

#[test]
fn the_decoder_skips_unknown_tags_and_reads_every_known_one() {
    let tlv = |tag: i128, value: &[u8]| {
        [encode_varint(tag).unwrap(), encode_varint(value.len() as i128).unwrap(), value.to_vec()].concat()
    };
    let dns: Vec<u8> = [&b"1.1.1.1"[..], b"tls://dns.example.com"]
        .iter()
        .flat_map(|item| [encode_varint(item.len() as i128).unwrap(), item.to_vec()].concat())
        .collect();
    let payload = [
        tlv(0, &encode_varint(2).unwrap()),
        tlv(0x40, b"future"),
        tlv(1, b"h"),
        tlv(2, b"a:1"),
        tlv(2, b"b:2"),
        tlv(3, b"sni.example"),
        tlv(4, b"\x00"),
        tlv(5, b"u"),
        tlv(6, b"p"),
        tlv(0x0A, b"\x01"),
        tlv(0x0B, b"aabb/ff00"),
        tlv(0x0D, &dns),
        tlv(0x0F, b"00ff"),
    ]
    .concat();
    let link = format!("tt://?{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload));
    let decoded = decode_deeplink(&link).unwrap();
    assert_eq!(decoded.addresses, ["a:1", "b:2"]);
    assert_eq!(decoded.custom_sni.as_deref(), Some("sni.example"));
    assert!(!decoded.has_ipv6 && decoded.anti_dpi);
    assert_eq!(decoded.client_random_prefix.as_deref(), Some("aabb/ff00"));
    assert_eq!(decoded.client_random_auth_key.as_deref(), Some("00ff"));
    assert_eq!(decoded.dns_upstreams, ["1.1.1.1", "tls://dns.example.com"]);
}

#[test]
fn a_bad_link_is_refused_without_echoing_it() {
    let good = encode_deeplink(&DeepLinkSpec::new("h", vec!["a:1".into()], "u", "p")).unwrap();
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut newer = engine.decode(&good["tt://?".len()..]).unwrap();
    newer[2] = 3;
    let truncated = format!("{}A", &good[..good.len() - 3]);
    let newer = format!("tt://?{}", engine.encode(newer));
    let unpadded = format!("tt://?{}", base64::engine::general_purpose::URL_SAFE.encode(b"\x01\x01h"));
    for bad in ["", "https://x", "tt://", "tt://?!!!", &truncated, &newer, "tt://?AAEC", &unpadded] {
        let error = decode_deeplink(bad).unwrap_err();
        assert!(!error.0.contains("ppppp"), "{bad}");
    }
    let missing = |spec: DeepLinkSpec| encode_deeplink(&spec).is_err();
    assert!(missing(DeepLinkSpec::new("", vec!["a:1".into()], "u", "p")));
    assert!(missing(DeepLinkSpec::new("h", vec![], "u", "p")));
    assert!(missing(DeepLinkSpec { upstream_protocol: 9, ..DeepLinkSpec::new("h", vec!["a:1".into()], "u", "p") }));
}

#[test]
fn toml_values_are_escaped_and_a_chain_is_split() {
    let options = TrusttunnelOptions {
        hostname: Some("h.example".into()),
        port: Some(8443),
        certificate_der_b64: None,
        name: Some("a\\b\"c\td".into()),
    };
    let grant = grant(Protocol::Trusttunnel, ProtocolOptions::Trusttunnel(options), "u");
    let toml = trusttunnel::render_toml(&grant, b"pa\"ss\\word", "").unwrap();
    assert!(toml.contains("password = \"pa\\\"ss\\\\word\"\n"), "{toml}");
    assert!(toml.contains("name = \"a\\\\b\\\"c\\td\"\n"), "{toml}");
    assert!(toml.contains("addresses = [\"h.example:8443\"]\n"), "{toml}");
    let (first, second) = certificates();
    let chain = [first.as_slice(), second].concat();
    let parts = trusttunnel::split_der(&chain).unwrap();
    assert_eq!(parts.len(), 2);
    assert_eq!(parts.concat(), chain);
    let pem = trusttunnel::certificate_pem(&base64::engine::general_purpose::STANDARD.encode(&chain)).unwrap();
    assert_eq!(pem.matches("BEGIN CERTIFICATE").count(), 2);
    for bad in [&b"\x00\x01"[..], b"\x30\x05\x01"] {
        assert!(trusttunnel::split_der(bad).is_err());
    }
}

#[test]
fn an_access_that_has_not_learned_its_endpoint_cannot_render() {
    let unlearned = grant(Protocol::Trusttunnel, ProtocolOptions::Trusttunnel(TrusttunnelOptions::default()), "x");
    let adapter = TrusttunnelAdapter::<TrusttunnelClient, XrayRouterClient>::new(TrusttunnelClient::new("/x", "t"), "");
    let error = adapter.render_artifacts(&unlearned, b"password-1234", "").unwrap_err();
    assert!(error.message.contains("not learned"));
    // A host from the settings stands in for a hostname the access did not record.
    let artifacts = adapter.render_artifacts(&unlearned, b"password-1234", "gate.example.com").unwrap();
    assert_eq!(decode_deeplink(&artifacts[0].value).unwrap().hostname.as_deref(), Some("gate.example.com"));
}

#[test]
fn a_config_needs_what_the_node_taught_and_a_host() {
    let unlearned = grant(Protocol::Amneziawg, ProtocolOptions::Amneziawg(AmneziawgOptions::default()), "x");
    let error = amneziawg::render_conf(&unlearned, &amneziawg::new_credential(), "vpn.example.com").unwrap_err();
    assert!(error.message.contains("not learned"));
}
