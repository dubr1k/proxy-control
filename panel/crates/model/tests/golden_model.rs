//! `panel-model` against what the Python panel (3.13.5, pydantic 2.13.4, FastAPI 0.142.2 in the
//! panel image) produced for the same inputs: `fixtures/model.json`, made by
//! `fixtures/generators/gen_model.py` (run through `fixtures/generators/run.sh`).

use indexmap::IndexMap;
use panel_core::errors::ApiError;
use panel_core::pyjson::{self, Options};
use panel_model::clients::{
    within_validity, AmneziawgOptions, Client, MieruOptions, MieruQuota, MtproxyOptions, NaiveOptions,
    TrusttunnelOptions,
};
use panel_model::fleet::{
    EgressDocument, GenerationDocument, ObservedEgress, ObservedGeneration, ObservedRelay, ObservedResource,
    PushRequest, PushResponse, RelayAccount, RelaySection, Resource, CONFLICT_CODES,
};
use panel_model::protocols::{
    applied_egress_from_view, egress_error, egress_target_from_view, router_target_from_view, AppliedDocument,
    EGRESS_ERROR_CODES,
};
use panel_model::routing::document::{
    attach_document, attached_to_router, canonical, document_digest, redact_diff, redact_document,
    router_direct_intent, telemt_direct_document, trusttunnel_direct_document, without_lane, ATTACH_PROTOCOLS,
    EGRESS_REASON_CODES, MTPROXY_BRIDGE_ADDRESS,
};
use panel_model::routing::{
    backend_for, backends_for, exit_hops, normalise_cidr, normalise_domain, normalise_exit, normalise_geo_code,
    normalise_lane, normalise_port, CompileStatus, Compiled, GeoKind, PolicyInput, Reason, RoutingPolicy, RoutingRule,
    RuleMatch, COMPILER_VERSION,
};
use panel_model::{metrics, pyrepr, Backend, Model, ValidationError, WireEnum};
use serde_json::{json, Map, Value};

fn fixture() -> Value {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/model.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

/// `json.dumps(value, ensure_ascii=False)`.
fn text(value: &Value) -> String {
    pyjson::dumps(value, &Options { ensure_ascii: false, ..Options::default() })
}

struct Outcome {
    body: Result<(String, String), ValidationError>,
    python: Result<(String, String), ValidationError>,
}

fn outcome<M: Model>(input: &Value) -> Outcome {
    let dumps = |model: M| (text(&model.dump()), model.dump_json());
    Outcome { body: M::validate_body(input).map(dumps), python: M::validate(input).map(dumps) }
}

fn validate(model: &str, input: &Value) -> Outcome {
    match model {
        "Resource" => outcome::<Resource>(input),
        "RelayAccount" => outcome::<RelayAccount>(input),
        "RelaySection" => outcome::<RelaySection>(input),
        "EgressDocument" => outcome::<EgressDocument>(input),
        "GenerationDocument" => outcome::<GenerationDocument>(input),
        "PushRequest" => outcome::<PushRequest>(input),
        "ObservedResource" => outcome::<ObservedResource>(input),
        "ObservedEgress" => outcome::<ObservedEgress>(input),
        "ObservedRelay" => outcome::<ObservedRelay>(input),
        "ObservedGeneration" => outcome::<ObservedGeneration>(input),
        "PushResponse" => outcome::<PushResponse>(input),
        "RuleMatch" => outcome::<RuleMatch>(input),
        "RoutingRule" => outcome::<RoutingRule>(input),
        "PolicyInput" => outcome::<PolicyInput>(input),
        "RoutingPolicy" => outcome::<RoutingPolicy>(input),
        "Reason" => outcome::<Reason>(input),
        "MieruQuota" => outcome::<MieruQuota>(input),
        "MtproxyOptions" => outcome::<MtproxyOptions>(input),
        "NaiveOptions" => outcome::<NaiveOptions>(input),
        "MieruOptions" => outcome::<MieruOptions>(input),
        "AmneziawgOptions" => outcome::<AmneziawgOptions>(input),
        "TrusttunnelOptions" => outcome::<TrusttunnelOptions>(input),
        "Client" => outcome::<Client>(input),
        other => panic!("unknown model {other}"),
    }
}

/// Inputs where Rust deliberately differs from Python (DIFFERENCES.md): Python accepted them.
fn deliberate_difference(model: &str, input: &Value) -> Option<&'static str> {
    if model == "TrusttunnelOptions" && input.get("hostname") == Some(&json!("tt.example\n")) {
        return Some("value_error");
    }
    if model == "Resource" && input.get("valid_from").is_some_and(|value| value.as_u64() == Some(1 << 63)) {
        return Some("int_parsing_size");
    }
    None
}

#[test]
fn every_model_validates_dumps_and_refuses_like_pydantic() {
    let fixture = fixture();
    let cases = fixture["validation"].as_array().unwrap();
    assert!(cases.len() > 300);
    let mut wrong = Vec::new();
    for case in cases {
        let model = case["model"].as_str().unwrap();
        let input = &case["input"];
        let result = validate(model, input);
        if let Some(kind) = deliberate_difference(model, input) {
            let error = result.body.expect_err("Rust refuses this input");
            assert_eq!(error.issues[0].kind, kind, "{model} {input}");
            continue;
        }
        let status = case["status"].as_u64().unwrap();
        match (&result.body, status) {
            (Ok((dump, _)), 200) => {
                if Some(dump.as_str()) != case["python"]["dump"].as_str() {
                    wrong.push(format!("{model} {input}: body dump {dump}"));
                }
            }
            (Err(error), 422) => {
                let body = String::from_utf8(ApiError::Validation(error.body_issues()).body_bytes()).unwrap();
                if body != case["body"].as_str().unwrap() {
                    wrong.push(format!("{model} {input}:\n  rust   {body}\n  python {}", case["body"]));
                }
            }
            (other, _) => wrong.push(format!("{model} {input}: status {status}, rust {other:?}")),
        }
        let python = &case["python"];
        match (&result.python, python["ok"].as_bool().unwrap()) {
            (Ok((dump, json)), true) => {
                if Some(dump.as_str()) != python["dump"].as_str() || Some(json.as_str()) != python["json"].as_str() {
                    wrong.push(format!("{model} {input}: dump {dump} / {json}"));
                }
            }
            (Err(error), false) => {
                if error.to_string() != python["str"].as_str().unwrap() {
                    wrong.push(format!("{model} {input}:\n  rust   {error}\n  python {}", python["str"]));
                }
            }
            (other, _) => wrong.push(format!("{model} {input}: model_validate {other:?}")),
        }
    }
    assert!(wrong.is_empty(), "{} of {} cases differ:\n{}", wrong.len(), cases.len(), wrong.join("\n"));
}

#[test]
fn generation_documents_keep_their_wire_form_stored_form_and_digests() {
    let fixture = fixture();
    let documents = fixture["fleet_documents"].as_array().unwrap();
    assert!(documents.len() >= 10);
    for case in documents {
        let name = case["name"].as_str().unwrap();
        let document = GenerationDocument::validate(&case["input"]).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(text(&document.wire()), case["wire"].as_str().unwrap(), "{name} wire");
        assert_eq!(document.dump_json(), case["stored"].as_str().unwrap(), "{name} stored");
        let digest = case["canonical_digest"].as_str().unwrap();
        assert_eq!(document.canonical_digest(), digest, "{name} digest");
        assert_eq!(document.content_digest(), case["content_digest"].as_str().unwrap(), "{name} content digest");
        // What the node stored and what travelled read back to the same digest.
        let stored: Value = serde_json::from_str(case["stored"].as_str().unwrap()).unwrap();
        assert_eq!(GenerationDocument::validate(&stored).unwrap().canonical_digest(), digest, "{name} reread");
        let wire: Value = serde_json::from_str(case["wire"].as_str().unwrap()).unwrap();
        assert_eq!(GenerationDocument::validate_body(&wire).unwrap(), document, "{name} rewired");
        let mut secrets: IndexMap<String, String> = document
            .resources
            .iter()
            .map(|resource| (resource.credential_ref.clone(), format!("pw-{}", resource.reference)))
            .collect();
        if let Some(relay) = &document.relay {
            for account in &relay.accounts {
                secrets.insert(account.credential_ref.clone(), "uuid".into());
            }
        }
        let request = PushRequest { expected_guid: document.node_guid.clone(), generation: document, secrets };
        request.check().unwrap();
        assert_eq!(text(&request.wire()), case["push_wire"].as_str().unwrap(), "{name} push wire");
        assert_eq!(request.dump_json(), case["push_stored"].as_str().unwrap(), "{name} push stored");
        let push: Value = serde_json::from_str(case["push_wire"].as_str().unwrap()).unwrap();
        assert_eq!(PushRequest::validate_body(&push).unwrap(), request, "{name} push read back");
    }
}

fn check_normaliser(entries: &Value, name: &str, run: impl Fn(&Value) -> Option<Result<Value, String>>) {
    let mut checked = 0;
    for entry in entries.as_array().unwrap() {
        let Some(result) = run(entry) else {
            // A non-string input: the Rust function takes `&str`, Python answered with its type error.
            assert!(!entry["ok"].as_bool().unwrap(), "{name} {entry}");
            continue;
        };
        checked += 1;
        match (result, entry["ok"].as_bool().unwrap()) {
            (Ok(value), true) => assert_eq!(value, entry["value"], "{name} {}", entry["input"]),
            (Err(message), false) => assert_eq!(message, entry["error"].as_str().unwrap(), "{name} {}", entry["input"]),
            (other, _) => panic!("{name} {}: rust {other:?}, python {entry}", entry["input"]),
        }
    }
    assert!(checked > 5, "{name}");
}

fn string_fn(
    f: impl Fn(&str) -> Result<String, panel_core::pytext::PyValueError>,
) -> impl Fn(&Value) -> Option<Result<Value, String>> {
    move |entry| entry["input"].as_str().map(|text| f(text).map(Value::String).map_err(|error| error.0))
}

#[test]
fn routing_normalisers_match_python() {
    let fixture = fixture();
    let functions = &fixture["functions"];
    check_normaliser(&functions["normalise_exit"], "normalise_exit", string_fn(normalise_exit));
    check_normaliser(&functions["normalise_domain"], "normalise_domain", string_fn(normalise_domain));
    check_normaliser(&functions["normalise_cidr"], "normalise_cidr", string_fn(normalise_cidr));
    check_normaliser(&functions["normalise_geo_code"], "normalise_geo_code", |entry| {
        let kind = GeoKind::from_wire(entry["kind"].as_str().unwrap()).unwrap();
        entry["input"].as_str().map(|text| normalise_geo_code(text, kind).map(Value::String).map_err(|error| error.0))
    });
    check_normaliser(&functions["normalise_lane"], "normalise_lane", |entry| match &entry["input"] {
        Value::Null => Some(normalise_lane(None).map(Value::String).map_err(|error| error.0)),
        Value::String(text) => Some(normalise_lane(Some(text)).map(Value::String).map_err(|error| error.0)),
        _ => None,
    });
    check_normaliser(&functions["normalise_port"], "normalise_port", |entry| {
        Some(normalise_port(&entry["input"]).map(|port| port.to_value()).map_err(|error| error.0))
    });
    for entry in functions["exit_hops"].as_array().unwrap() {
        let (hops, via) = exit_hops(entry["input"].as_str());
        assert_eq!(json!([hops, via]), entry["value"], "{entry}");
    }
    for entry in functions["backends_for"].as_array().unwrap() {
        let backends: Vec<&str> =
            backends_for(entry["input"].as_str().unwrap()).into_iter().map(Backend::as_str).collect();
        assert_eq!(json!(backends), entry["value"], "{entry}");
    }
}

#[test]
fn constants_match_python() {
    let fixture = fixture();
    let constants = &fixture["functions"]["constants"];
    for (protocol, backend) in constants["BACKEND_FOR"].as_object().unwrap() {
        assert_eq!(backend_for(protocol).map(Backend::as_str), backend.as_str());
    }
    use panel_model::routing as r;
    assert_eq!(json!(r::LANE_PROTOCOLS), constants["LANE_PROTOCOLS"]);
    assert_eq!(json!(COMPILER_VERSION), constants["COMPILER_VERSION"]);
    assert_eq!(json!(r::SNIFFED_PROTOCOLS), constants["SNIFFED_PROTOCOLS"]);
    assert_eq!(json!(r::AMNEZIAWG_WHOLE_ONLY), constants["AMNEZIAWG_WHOLE_ONLY"]);
    assert_eq!(json!(r::LANES_UNSUPPORTED_AMNEZIAWG), constants["LANES_UNSUPPORTED_AMNEZIAWG"]);
    assert_eq!(json!(r::LANES_UNSUPPORTED_TRUSTTUNNEL), constants["LANES_UNSUPPORTED_TRUSTTUNNEL"]);
    assert_eq!(json!(EGRESS_REASON_CODES), constants["EGRESS_REASON_CODES"]);
    assert_eq!(json!(EGRESS_ERROR_CODES), constants["EGRESS_ERROR_CODES"]);
    let attach: Map<String, Value> =
        ATTACH_PROTOCOLS.iter().map(|protocol| (protocol.to_string(), attach_document(protocol).unwrap())).collect();
    assert_eq!(text(&Value::Object(attach)), text(&constants["ATTACH_DOCUMENTS"]));
    assert_eq!(trusttunnel_direct_document(), constants["TRUSTTUNNEL_DIRECT_DOCUMENT"]);
    assert_eq!(telemt_direct_document(), constants["TELEMT_DIRECT_DOCUMENT"]);
    assert_eq!(json!(MTPROXY_BRIDGE_ADDRESS), constants["MTPROXY_BRIDGE_ADDRESS"]);
    assert_eq!(text(&router_direct_intent()), text(&constants["ROUTER_DIRECT_INTENT"]));
    assert_eq!(json!(CONFLICT_CODES), constants["CONFLICT_CODES"]);
    assert_eq!(json!(panel_model::clients::PROTOCOLS), constants["PROTOCOLS"]);
    let versions: Vec<&str> = panel_model::clients::AwgVersion::ALL.iter().map(|version| version.as_str()).collect();
    assert_eq!(json!(versions), constants["AWG_VERSIONS"]);
    assert_eq!(json!(panel_model::clients::AWG_OBFUSCATION_KEYS), constants["AWG_OBFUSCATION_KEYS"]);
    let protocols: Vec<&str> = panel_model::Protocol::ALL.iter().map(|protocol| protocol.as_str()).collect();
    assert_eq!(json!(protocols), constants["PROTOCOLS"]);
}

#[test]
fn egress_document_helpers_match_python() {
    let fixture = fixture();
    let functions = &fixture["functions"];
    for (protocol, expected) in functions["attach_document"].as_object().unwrap() {
        assert_eq!(&text(&attach_document(protocol).unwrap()), expected.as_str().unwrap());
    }
    for entry in functions["attached_to_router"].as_array().unwrap() {
        let value = attached_to_router(entry["protocol"].as_str().unwrap(), &entry["document"]);
        assert_eq!(json!(value), entry["value"], "{entry}");
    }
    for entry in functions["canonical"].as_array().unwrap() {
        assert_eq!(canonical(&entry["document"]), entry["canonical"].as_str().unwrap());
        assert_eq!(document_digest(&entry["document"]), entry["digest"].as_str().unwrap());
    }
    for entry in functions["redact_document"].as_array().unwrap() {
        assert_eq!(text(&redact_document(&entry["document"])), entry["value"].as_str().unwrap(), "{entry}");
    }
    let lines: Vec<String> = serde_json::from_value(functions["redact_diff"]["lines"].clone()).unwrap();
    assert_eq!(json!(redact_diff(&lines)), functions["redact_diff"]["value"]);
    for entry in functions["without_lane"].as_array().unwrap() {
        let value = without_lane(&entry["document"], entry["lane"].as_str().unwrap());
        assert_eq!(text(&value), entry["value"].as_str().unwrap(), "{entry}");
    }
}

fn applied(document: &Option<AppliedDocument>) -> Value {
    document.as_ref().map_or(Value::Null, AppliedDocument::to_value)
}

#[test]
fn adapter_view_parsers_and_egress_errors_match_python() {
    let fixture = fixture();
    let functions = &fixture["functions"];
    for entry in functions["egress_target_from_view"].as_array().unwrap() {
        let backend = Backend::from_wire(entry["backend"].as_str().unwrap()).unwrap();
        let target =
            egress_target_from_view(entry["protocol"].as_str().unwrap(), backend, entry["view"].as_object().unwrap());
        let value = json!({
            "protocol": target.protocol, "backend": target.backend.as_str(), "capabilities": target.capabilities,
            "providers": target.providers, "revision": target.revision, "applied": applied(&target.applied),
            "mode": target.mode.as_str(), "restart_required": target.restart_required, "warnings": target.warnings,
            "runtime_version": target.runtime_version, "router_attached": target.router_attached,
        });
        assert_eq!(value, entry["value"], "{entry}");
    }
    for entry in functions["router_target_from_view"].as_array().unwrap() {
        let target = router_target_from_view(entry["service"].as_str().unwrap(), entry["view"].as_object().unwrap());
        let value = json!({
            "available": target.available, "service": target.service, "capabilities": target.capabilities,
            "providers": target.providers, "revision": target.revision, "applied": applied(&target.applied),
            "xray_version": target.xray_version, "restart_required": target.restart_required, "reason": target.reason,
        });
        assert_eq!(value, entry["value"], "{entry}");
    }
    for entry in functions["applied_egress_from_view"].as_array().unwrap() {
        let applied = applied_egress_from_view(entry["view"].as_object().unwrap());
        let value = json!({"revision": applied.revision, "digest": applied.digest,
                           "readback_sha256": applied.readback_sha256, "replayed": applied.replayed});
        assert_eq!(value, entry["value"], "{entry}");
    }
    for entry in functions["egress_error"].as_array().unwrap() {
        let error = egress_error(
            entry["runtime"].as_str().unwrap(),
            entry["status"].as_u64().unwrap() as u16,
            entry["code"].as_str(),
        );
        let class = if error.is_manual_intervention() { "ManualInterventionRequired" } else { "AdapterError" };
        assert_eq!(class, entry["class"].as_str().unwrap());
        assert_eq!(error.to_string(), entry["message"].as_str().unwrap());
        assert_eq!(error.code.as_deref(), entry["value_code"].as_str());
        assert_eq!(error.already_gone, entry["already_gone"].as_bool().unwrap());
    }
}

#[test]
fn small_helpers_match_python() {
    let fixture = fixture();
    let functions = &fixture["functions"];
    for entry in functions["within_validity"].as_array().unwrap() {
        let args = entry["args"].as_array().unwrap();
        let value = within_validity(args[0].as_i64(), args[1].as_i64(), args[2].as_i64().unwrap());
        assert_eq!(json!(value), entry["value"], "{entry}");
    }
    let python = &functions["metrics"];
    assert_eq!(json!(metrics::all_series()), python["ALL_SERIES"]);
    let ranges: Map<String, Value> =
        metrics::RANGES.iter().map(|(name, seconds)| (name.to_string(), json!(seconds))).collect();
    assert_eq!(text(&Value::Object(ranges)), text(&python["RANGES"]));
    let retention: Map<String, Value> =
        metrics::RETENTION.iter().map(|(resolution, keep)| (resolution.to_string(), json!(keep))).collect();
    assert_eq!(Value::Object(retention), python["RETENTION"]);
    assert_eq!(json!([metrics::POINTS_MIN, metrics::POINTS_MAX, metrics::POINTS_DEFAULT]), python["POINTS"]);
    for pair in python["resolution_for"].as_array().unwrap() {
        assert_eq!(json!(metrics::resolution_for(pair[0].as_i64().unwrap())), pair[1]);
    }
    for pair in python["is_bytes_series"].as_array().unwrap() {
        assert_eq!(json!(metrics::is_bytes_series(pair[0].as_str().unwrap())), pair[1]);
    }
    for name in metrics::all_series() {
        assert!(metrics::is_series(&name));
    }
    for entry in functions["repr"].as_array().unwrap() {
        assert_eq!(pyrepr::repr(&entry["value"]), entry["repr"].as_str().unwrap(), "{entry}");
        assert_eq!(pyrepr::str(&entry["value"]), entry["str"].as_str().unwrap(), "{entry}");
    }
}

fn compiled_from(dump: &Value) -> Compiled {
    let strings = |key: &str| -> Vec<String> { serde_json::from_value(dump[key].clone()).unwrap() };
    let optional = |key: &str| -> Option<String> { dump[key].as_str().map(str::to_string) };
    let some = |key: &str| -> Option<Value> { (!dump[key].is_null()).then(|| dump[key].clone()) };
    Compiled {
        status: CompileStatus::from_wire(dump["status"].as_str().unwrap()).unwrap(),
        reasons: dump["reasons"].as_array().unwrap().iter().map(|reason| Reason::validate(reason).unwrap()).collect(),
        warnings: strings("warnings"),
        document: some("document"),
        digest: optional("digest"),
        diff: strings("diff"),
        restart_required: dump["restart_required"].as_bool().unwrap(),
        rollback: some("rollback"),
        compiler_version: dump["compiler_version"].as_str().unwrap().to_string(),
        backend: optional("backend"),
        runtime_version: optional("runtime_version"),
        attach: some("attach"),
    }
}

#[test]
fn compiled_previews_and_policy_helpers_match_python() {
    let fixture = fixture();
    let functions = &fixture["functions"];
    for entry in functions["compiled_redacted"].as_array().unwrap() {
        let dump: Value = serde_json::from_str(entry["dump"].as_str().unwrap()).unwrap();
        let compiled = compiled_from(&dump);
        assert_eq!(text(&compiled.dump()), entry["dump"].as_str().unwrap());
        assert_eq!(text(&compiled.redacted()), entry["redacted"].as_str().unwrap());
    }
    let cases = fixture["validation"].as_array().unwrap();
    let stored = cases.iter().filter(|case| case["model"] == "RoutingPolicy").nth(2).unwrap();
    let policy = RoutingPolicy::validate(&stored["input"]).unwrap();
    assert_eq!(
        text(&PolicyInput::from_policy(&policy).dump()),
        functions["policy_input_from_policy"].as_str().unwrap()
    );
    let intent_case = cases.iter().filter(|case| case["model"] == "PolicyInput").nth(9).unwrap();
    let intent = PolicyInput::validate(&intent_case["input"]).unwrap().intent;
    assert_eq!(json!(intent.exits()), functions["intent_exits"]["exits"]);
    assert_eq!(json!(intent.node_exits()), functions["intent_exits"]["node_exits"]);
    let custom = PolicyInput::validate(&json!({"default_action": "egress", "default_egress": "exit:e1", "rules": [
        {"match": {"domains": ["a.com"]}, "action": "egress", "egress": "exit:e2", "enabled": false},
        {"match": {"domains": ["a.com"]}, "action": "egress", "egress": "EXIT:e3"}]}))
    .unwrap();
    assert_eq!(json!(custom.intent.custom_exits()), functions["intent_exits"]["custom_exits"]);
}
