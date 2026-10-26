//! `panel/tests/test_fleet_v2_protocol.py`, and the wire-form unit parts of
//! `test_routing_fleet.py`, `test_routing_fleet_router.py` and `test_routing_fleet_chains.py`.

use serde_json::{json, Value};

use super::*;
use crate::routing::document::{attach_document, document_digest};

fn resource(reference: &str, protocol: &str, user: &str, desired: &str, credential: &str, options: Value) -> Value {
    json!({"ref": reference, "protocol": protocol, "runtime_username": user, "desired_state": desired,
           "credential_ref": credential, "credential_origin": "caller", "options": options})
}

fn doc_value(overrides: Value) -> Value {
    let mut base = json!({
        "node_guid": "n".repeat(36), "master_guid": "m".repeat(36), "generation": 3, "previous_generation": 2,
        "created_at": 1, "created_by": "owner",
        "resources": [resource("grant:a", "naive", "alice", "enabled", "grant:a:1", json!({"quota_bytes": 5}))],
    });
    for (key, value) in overrides.as_object().unwrap() {
        base[key] = value.clone();
    }
    base
}

fn doc(overrides: Value) -> Result<GenerationDocument, ValidationError> {
    GenerationDocument::validate(&doc_value(overrides))
}

use crate::validate::ValidationError;

#[test]
fn digest_is_order_independent_and_secret_free() {
    let one = doc(json!({})).unwrap();
    let a = resource("grant:a", "naive", "alice", "enabled", "grant:a:1", json!({"quota_bytes": 5}));
    let b = resource("grant:b", "mieru", "bob", "disabled", "grant:b:2", json!({"quotas": []}));
    let two = doc(json!({"resources": [b.clone(), a.clone()]})).unwrap();
    assert_ne!(one.canonical_digest(), two.canonical_digest());
    assert_eq!(two.canonical_digest(), doc(json!({"resources": [a, b]})).unwrap().canonical_digest());
    assert!(!text_of(&one.dump()).contains("secret"));
}

fn text_of(value: &Value) -> String {
    panel_core::pyjson::dumps_default(value)
}

#[test]
fn unknown_protocol_state_or_extra_field_is_refused() {
    let base = resource("x", "naive", "a", "enabled", "x:1", json!({}));
    let mut bad = base.clone();
    bad["protocol"] = json!("xray");
    assert!(Resource::validate(&bad).is_err());
    let mut bad = base;
    bad["desired_state"] = json!("paused");
    assert!(Resource::validate(&bad).is_err());
    let push = json!({"expected_guid": "g", "generation": doc_value(json!({})), "secrets": {}, "shell": "rm -rf /"});
    assert!(PushRequest::validate(&push).is_err());
}

#[test]
fn generation_must_be_at_least_one() {
    assert!(doc(json!({"generation": 0, "previous_generation": 0})).is_err());
}

#[test]
fn push_secrets_must_reference_document_refs() {
    let push = |secrets: Value| {
        PushRequest::validate(
            &json!({"expected_guid": "n".repeat(36), "generation": doc_value(json!({})), "secrets": secrets}),
        )
    };
    let error = push(json!({"grant:zzz:1": "pw"})).unwrap_err();
    assert_eq!(error.issues[0].msg, "Value error, secrets for unknown refs: ['grant:zzz:1']");
    let ok = push(json!({"grant:a:1": "pw"})).unwrap();
    assert_eq!(ok.secrets["grant:a:1"], "pw");
}

#[test]
fn two_resources_cannot_name_the_same_protocol_and_runtime_user() {
    let first = resource("grant:a", "naive", "alice", "enabled", "grant:a:1", json!({"quota_bytes": 5}));
    let colliding = resource("grant:a-again", "naive", "alice", "disabled", "grant:a:2", json!({}));
    let error = doc(json!({"resources": [first, colliding]})).unwrap_err();
    assert_eq!(error.issues[0].msg, "Value error, duplicate resource for naive/alice");
}

#[test]
fn observed_resource_carries_learned_link_facts_but_never_a_credential() {
    let item = ObservedResource::validate(&json!({"ref": "grant:1", "protocol": "mtproxy", "runtime_username": "a",
                                                  "state": "enabled", "learned": {"host": "proxy.example", "port": 443}}))
    .unwrap();
    assert_eq!(item.learned["host"], Learned::Str("proxy.example".into()));
    assert_eq!(item.learned["port"], Learned::Int(443));
    let bare = ObservedResource::validate(&json!({"ref": "grant:1", "protocol": "naive", "runtime_username": "a",
                                                  "state": "enabled"}))
    .unwrap();
    assert!(bare.learned.is_empty());
    let nine: serde_json::Map<String, Value> = (0..9).map(|i| (format!("k{i}"), json!(i))).collect();
    assert!(ObservedResource::validate(&json!({"ref": "grant:1", "protocol": "mtproxy", "runtime_username": "a",
                                               "state": "enabled", "learned": nine}))
    .is_err());
}

#[test]
fn observed_reports_ignore_unknown_fields_but_the_node_still_refuses_them() {
    let payload = json!({"applied_generation": 1, "digest": "d", "reconcile_state": "converged", "reported_at": 1,
                         "resources": [{"ref": "grant:1", "protocol": "naive", "runtime_username": "a", "state": "enabled",
                                        "future_field": {"x": 1}}],
                         "another_future_field": true});
    let observed = ObservedGeneration::validate(&payload).unwrap();
    assert!(observed.dump().get("another_future_field").is_none());
    assert!(observed.resources[0].learned.is_empty() && observed.resources[0].dump().get("future_field").is_none());
    let mut missing = payload["resources"][0].clone();
    missing["state"] = json!("missing");
    assert_eq!(ObservedResource::validate(&missing).unwrap().state, ObservedState::Missing);
    let response = PushResponse::validate(&json!({"observed": payload, "credentials": {}, "future": 1})).unwrap();
    assert!(response.dump().get("future").is_none());
    let mut strict = doc(json!({})).unwrap().dump();
    strict["future_field"] = json!(1);
    assert!(GenerationDocument::validate(&strict).is_err());
}

const NAIVE_WARP: &str = r#"{"schema": 1, "upstream": {"provider": "warp"}, "acl": []}"#;

fn egress_value(document: &Value, backend: &str, extra: Value) -> Value {
    let mut section = json!({"backend": backend, "policy_id": "p-1", "policy_revision": 1, "document": document,
                             "digest": document_digest(document)});
    for (key, value) in extra.as_object().unwrap() {
        section[key] = value.clone();
    }
    section
}

/// `test_routing_fleet.py::test_egress_section_is_part_of_the_digest_and_omitted_when_absent`.
#[test]
fn egress_section_is_part_of_the_digest_and_omitted_when_absent() {
    let warp: Value = serde_json::from_str(NAIVE_WARP).unwrap();
    let block = json!({"schema": 1, "upstream": null, "acl": [{"deny": ["a.example"]}]});
    let plain = doc(json!({})).unwrap();
    assert!(plain.wire().get("egress").is_none());
    let request = PushRequest { expected_guid: "n".repeat(36), generation: plain.clone(), secrets: IndexMap::new() };
    assert!(request.wire()["generation"].get("egress").is_none());
    assert_eq!(plain.canonical_digest(), GenerationDocument::validate(&plain.wire()).unwrap().canonical_digest());
    let with_egress = doc(json!({"egress": {"naive": egress_value(&warp, "naive_native", json!({}))}})).unwrap();
    assert_eq!(with_egress.wire()["egress"]["naive"]["digest"], json!(document_digest(&warp)));
    assert_ne!(with_egress.canonical_digest(), plain.canonical_digest());
    let blocked = doc(json!({"egress": {"naive": egress_value(&block, "naive_native", json!({}))}})).unwrap();
    assert_ne!(with_egress.canonical_digest(), blocked.canonical_digest());
    assert!(doc(json!({"egress": {"socks": egress_value(&warp, "naive_native", json!({}))}})).is_err());
    let mut wire = plain.wire();
    wire["egress"] = json!({"naive": egress_value(&warp, "naive_native", json!({"x": 1}))});
    assert!(GenerationDocument::validate(&wire).is_err());
}

fn huge() -> Value {
    let deny: Vec<String> = (0..300).map(|i| format!("{}{i:04}.example", "x".repeat(60))).collect();
    json!({"schema": 1, "upstream": null, "acl": [{"deny": deny}]})
}

/// `test_routing_fleet.py::test_egress_document_validates_digest_and_size`.
#[test]
fn egress_document_validates_digest_and_size() {
    let warp: Value = serde_json::from_str(NAIVE_WARP).unwrap();
    let mut wrong = egress_value(&warp, "naive_native", json!({}));
    wrong["digest"] = json!("0".repeat(64));
    assert!(EgressDocument::validate(&wrong).is_err());
    assert!(EgressDocument::validate(&egress_value(&huge(), "naive_native", json!({}))).is_err());
    assert!(EgressDocument::validate(&egress_value(&warp, "xray", json!({}))).is_err());
}

/// `test_routing_fleet_router.py::test_companion_and_passthrough_are_in_the_digest_and_omitted_when_absent`.
#[test]
fn companion_and_passthrough_are_in_the_digest_and_omitted_when_absent() {
    let direct = json!({"schema": 1, "upstream": null, "acl": []});
    let intent = json!({"schema": 1, "default": {"action": "egress", "egress": "warp"}, "rules": []});
    let plain = doc(json!({"egress": {"naive": egress_value(&direct, "naive_native", json!({}))}})).unwrap();
    let wire = plain.wire()["egress"]["naive"].clone();
    assert!(wire.get("companion").is_none() && wire.get("passthrough").is_none());
    assert_eq!(plain.canonical_digest(), GenerationDocument::validate(&plain.wire()).unwrap().canonical_digest());
    let companion = attach_document("naive").unwrap();
    let attached =
        doc(json!({"egress": {"naive": egress_value(&intent, "xray_router", json!({"companion": companion}))}}))
            .unwrap();
    let attached_wire = attached.wire()["egress"]["naive"].clone();
    assert_eq!(attached_wire["companion"], companion);
    assert_eq!(attached_wire["backend"], json!("xray_router"));
    assert_ne!(attached.canonical_digest(), plain.canonical_digest());
    assert_eq!(attached.canonical_digest(), GenerationDocument::validate(&attached.wire()).unwrap().canonical_digest());
    let flagged =
        doc(json!({"egress": {"naive": egress_value(&direct, "naive_native", json!({"passthrough": true}))}})).unwrap();
    assert_eq!(flagged.wire()["egress"]["naive"]["passthrough"], json!(true));
    assert_ne!(flagged.canonical_digest(), plain.canonical_digest());
    let mut future = plain.wire();
    let mut section = wire.clone();
    section["future"] = json!(1);
    future["egress"] = json!({"naive": section});
    assert!(GenerationDocument::validate(&future).is_err());
    let error =
        EgressDocument::validate(&egress_value(&intent, "xray_router", json!({"companion": huge()}))).unwrap_err();
    assert!(error.to_string().contains("companion"));
}

/// `test_routing_fleet_chains.py::test_relay_and_lane_are_in_the_digest_and_omitted_when_absent`.
#[test]
fn relay_and_lane_are_in_the_digest_and_omitted_when_absent() {
    let email = format!("relay:{}:direct", "b".repeat(32));
    let plain = doc(json!({})).unwrap();
    let wire = plain.wire();
    assert!(wire.get("relay").is_none() && wire["resources"][0].get("lane").is_none());
    assert_eq!(plain.canonical_digest(), GenerationDocument::validate(&wire).unwrap().canonical_digest());
    let mut laned_resource = resource("grant:a", "naive", "alice", "enabled", "grant:a:1", json!({}));
    laned_resource["lane"] = json!("own");
    let relay = json!({"enabled": true, "port": 45443, "server_name": "node.example",
                       "accounts": [{"email": email, "credential_ref": "relay-secret:1"}]});
    let laned = doc(json!({"resources": [laned_resource.clone()], "relay": relay})).unwrap();
    let laned_wire = laned.wire();
    assert_eq!(laned_wire["resources"][0]["lane"], json!("own"));
    assert_eq!(laned_wire["relay"]["accounts"], json!([{"email": email, "credential_ref": "relay-secret:1"}]));
    assert_ne!(laned.canonical_digest(), plain.canonical_digest());
    assert_eq!(laned.canonical_digest(), GenerationDocument::validate(&laned_wire).unwrap().canonical_digest());
    let secrets: IndexMap<String, String> = [("relay-secret:1".to_string(), "uuid-direct".to_string())].into();
    let request = PushRequest { expected_guid: "n".repeat(36), generation: laned, secrets: secrets.clone() };
    request.check().unwrap();
    assert_eq!(request.wire()["secrets"], json!({"relay-secret:1": "uuid-direct"}));
    assert!(!text_of(&request.generation.wire()).contains("uuid-direct"));
    assert!(PushRequest { expected_guid: "n".repeat(36), generation: plain, secrets }.check().is_err());
    laned_resource["lane"] = json!("theirs");
    assert!(Resource::validate(&laned_resource).is_err());
    let bogus = json!({"enabled": true, "port": 45443, "server_name": "node.example",
                       "accounts": [{"email": "bogus", "credential_ref": "x:1"}]});
    assert!(RelaySection::validate(&bogus).is_err());
}

#[test]
fn content_digest_ignores_numbering_and_authorship() {
    let first = doc(json!({})).unwrap();
    let later =
        doc(json!({"generation": 9, "previous_generation": 8, "created_at": 99, "created_by": "system"})).unwrap();
    assert_ne!(first.canonical_digest(), later.canonical_digest());
    assert_eq!(first.content_digest(), later.content_digest());
}

#[test]
fn initial_observation_is_what_a_fresh_node_reports() {
    let initial = ObservedGeneration::initial().dump();
    assert_eq!(
        panel_core::pyjson::compact(&initial),
        r#"{"applied_generation":0,"digest":"","reconcile_state":"idle","resources":[],"reported_at":0,"egress":{},"relay":null}"#
    );
}

#[test]
fn conflicts_default_their_message_to_the_code() {
    assert_eq!(GenerationConflict::new(ConflictCode::StaleGeneration, "").to_string(), "stale_generation");
    assert_eq!(GenerationConflict::new(ConflictCode::GuidMismatch, "wrong node").to_string(), "wrong node");
    let codes: Vec<&str> = ConflictCode::ALL.iter().map(|code| code.as_str()).collect();
    assert_eq!(codes, CONFLICT_CODES);
}

use crate::common::WireEnum;
