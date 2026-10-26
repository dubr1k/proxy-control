//! The model tests of `panel/tests/test_clients_domain.py`, `test_amneziawg.py` and
//! `test_trusttunnel.py` (`options_are_bounded`); the store and service tests are WP7's.

use serde_json::json;

use super::*;
use crate::validate::Model;

fn grant(protocol: Protocol, options: ProtocolOptions) -> AccessGrant {
    AccessGrant {
        protocol,
        options,
        id: "g1".into(),
        client_id: "c1".into(),
        node_id: "local".into(),
        endpoint_id: "default".into(),
        runtime_username: "alice".into(),
        secret_ref: None,
        desired_state: GrantDesiredState::Enabled,
        observed_state: GrantObservedState::Unknown,
        valid_from: None,
        valid_until: None,
        origin: GrantOrigin::Imported,
        own_lane: false,
        label: None,
        created_at: 1,
        updated_at: 1,
    }
}

fn client(state: ClientState) -> Client {
    Client { id: "c1".into(), display_name: "Sergey".into(), state, metadata: Map::new(), created_at: 1, updated_at: 1 }
}

#[test]
fn options_are_typed_and_secret_free() {
    let naive = ProtocolOptions::Naive(NaiveOptions { quota_bytes: Some(1) });
    let error = GrantIntent::new(Protocol::Mieru, "a", naive.clone()).unwrap_err();
    assert_eq!(error.issues[0].msg, "Value error, mieru requires MieruOptions");
    assert!(GrantIntent::new(Protocol::Naive, "a b", naive).is_err());
    // A rendered link, not a template: the real credential would be stored in the row.
    assert!(
        MieruOptions::validate(&json!({"quotas": [], "share_template": "mierus://u:realpassword@h?port=1"})).is_err()
    );
    assert!(MtproxyOptions::validate(&json!({"max_tcp_conns": 0})).is_err());
    let intent = GrantIntent::new(Protocol::Mieru, "alice", ProtocolOptions::Mieru(MieruOptions::default())).unwrap();
    assert_eq!((intent.node_id.as_str(), intent.endpoint_id.as_str()), ("local", "default"));
    assert!(MieruOptions::validate(
        &json!({"quotas": [], "share_template": "mierus://{username}:{password}@h?port=1"})
    )
    .is_ok());
}

#[test]
fn a_grant_round_trips_through_its_dump_with_typed_options() {
    let options = MieruOptions::validate(&json!({"quotas": [{"days": 30, "megabytes": 10}]})).unwrap();
    let stored = grant(Protocol::Mieru, ProtocolOptions::Mieru(options));
    let loaded = AccessGrant::validate(&stored.dump()).unwrap();
    assert_eq!(loaded, stored);
    let ProtocolOptions::Mieru(options) = &loaded.options else { panic!("mieru options") };
    assert_eq!(options.quotas[0].megabytes, 10);
    let json = loaded.options.dump_json();
    assert_eq!(json, r#"{"quotas":[{"days":30,"megabytes":10}],"share_template":null}"#);
    let reread: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(ProtocolOptions::validate(Protocol::Mieru, &reread).unwrap(), loaded.options);
}

#[test]
fn suspended_client_compiles_every_grant_as_disabled() {
    let now = 1_000;
    let grant = grant(Protocol::Naive, ProtocolOptions::Naive(NaiveOptions::default()));
    assert!(effective_enabled(&grant, &client(ClientState::Active), now));
    assert!(!effective_enabled(&grant, &client(ClientState::Suspended), now));
    let active = client(ClientState::Active);
    assert!(!effective_enabled(&AccessGrant { valid_until: Some(now - 1), ..grant.clone() }, &active, now));
    assert!(!effective_enabled(&AccessGrant { valid_from: Some(now + 1), ..grant.clone() }, &active, now));
    assert!(!effective_enabled(&AccessGrant { desired_state: GrantDesiredState::Disabled, ..grant }, &active, now));
}

/// `test_amneziawg.py::test_options_are_bounded`.
#[test]
fn amneziawg_options_are_bounded() {
    assert_eq!(AmneziawgOptions::default().version, AwgVersion::V2_0);
    assert_eq!(AmneziawgOptions::validate(&json!({})).unwrap(), AmneziawgOptions::default());
    for bad in [
        json!({"version": "1.0"}),
        json!({"version": "4.0"}),
        json!({"address": "999.1.1.1"}),
        json!({"port": 0}),
        json!({"obfuscation": {"Evil": "1"}}),
        json!({"obfuscation": {"Jc": "1\nPostUp = rm -rf /"}}),
        json!({"dns": ["not-an-ip"]}),
        json!({"unknown": 1}),
    ] {
        assert!(AmneziawgOptions::validate(&bad).is_err(), "{bad}");
    }
    assert!(GrantIntent::new(Protocol::Amneziawg, "x", ProtocolOptions::Mieru(MieruOptions::default())).is_err());
}

/// `test_trusttunnel.py::test_options_are_bounded`.
#[test]
fn trusttunnel_options_are_bounded() {
    assert_eq!(TrusttunnelOptions::validate(&json!({})).unwrap().hostname, None);
    for bad in [
        json!({"hostname": "bad host"}),
        json!({"hostname": "-x.example"}),
        json!({"port": 0}),
        json!({"port": 70000}),
        json!({"certificate_der_b64": "not base64!"}),
        json!({"name": ""}),
        json!({"name": "x".repeat(65)}),
        json!({"unknown": 1}),
    ] {
        assert!(TrusttunnelOptions::validate(&bad).is_err(), "{bad}");
    }
    assert!(GrantIntent::new(Protocol::Trusttunnel, "x", ProtocolOptions::Mieru(MieruOptions::default())).is_err());
}

#[test]
fn strict_base64_follows_python_3_13() {
    for good in ["", "QUJD", "QQ==", "QUJ=", "QUJDRA=="] {
        assert!(is_strict_base64(good), "{good}");
    }
    for bad in ["QUJD==", "QQ=", "QQ", "Q", "==", "QU JD", "Q=Q=", "QQ==QQ==", "Ж", "QUJDRA="] {
        assert!(!is_strict_base64(bad), "{bad}");
    }
}

#[test]
fn share_templates_are_shapes_not_links() {
    assert!(MieruOptions::check_template("{username}{password}").is_ok());
    assert!(MieruOptions::check_template("mierus://{username}:{password}@h").is_ok());
    assert!(MieruOptions::check_template("mierus://a/{username}:{password}@h").is_ok());
    assert!(MieruOptions::check_template("mierus://real@h {username}{password}").is_err());
    assert!(MieruOptions::check_template("no placeholders").is_err());
}

#[test]
fn grants_check_their_label_and_options() {
    let naive = grant(Protocol::Naive, ProtocolOptions::Naive(NaiveOptions::default()));
    naive.check().unwrap();
    assert!(AccessGrant { label: Some(String::new()), ..naive.clone() }.check().is_err());
    assert!(AccessGrant { protocol: Protocol::Mieru, ..naive.clone() }.check().is_err());
    let laned = AccessGrant { own_lane: true, label: Some("Телефон".into()), ..naive };
    assert_eq!(laned.dump()["routing_lane"], json!("own"));
    assert_eq!(AccessGrant::validate(&laned.dump()).unwrap(), laned);
}
