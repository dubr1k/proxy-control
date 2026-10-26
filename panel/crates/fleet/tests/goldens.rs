//! The central↔node exchanges recorded from the Python panels (`panel/tests/goldens/fleet/fleet.json`,
//! 38 wire exchanges: identity, status, inventory and five pushes) replayed against the Rust node
//! over the same memory doubles: same status, same body bytes, same stored generations and
//! resources, same audit details. Plus the node-side refusals of `errors/error_bodies.json`.

mod support;

use panel_core::pyjson;
use panel_fleet::node::service::NodeResult;
use panel_fleet::node::{NodeConfig, NodeFailure};
use panel_model::fleet::PushRequest;
use panel_model::validate::Model;
use serde_json::Value;
use support::{golden, Hosts, Node, NodeOptions, StaticVersions};

fn render(result: NodeResult<(u16, Value)>) -> (u16, String) {
    match result {
        Ok((status, body)) => (status, pyjson::compact_utf8(&body)),
        Err(NodeFailure::Api(error)) => (error.status(), String::from_utf8(error.body_bytes()).unwrap()),
        Err(NodeFailure::Internal(message)) => panic!("unhandled error: {message}"),
    }
}

async fn push(node: &Node, body: &Value) -> (u16, String) {
    let request = match PushRequest::validate_body(body) {
        Ok(request) => request,
        Err(error) => {
            let error = error.to_api_error();
            return (error.status(), String::from_utf8(error.body_bytes()).unwrap());
        }
    };
    let accepted = match node.node.accept(request).await {
        Ok(accepted) => accepted,
        Err(error) => return render(Err(error)),
    };
    render(node.node.apply_pushed(accepted.generation, |work| drop(tokio::spawn(work))).await)
}

fn replay_node(fleet: &Value) -> Node {
    let status = serde_json::from_str::<Value>(fleet["wire"][1]["response"]["body"]["text"].as_str().unwrap()).unwrap();
    Node::new(NodeOptions {
        guid: fleet["node_id"].as_str().unwrap().into(),
        panel_version: "3.3.0".into(),
        config: NodeConfig {
            naive_enabled: true,
            mieru_enabled: true,
            amneziawg_enabled: true,
            trusttunnel_enabled: true,
            metrics_enabled: true,
            mtproxy_host: "proxy.example.com".into(),
            naive_public_host: "naive.example.com".into(),
            amneziawg_public_host: "awg.example.com".into(),
            trusttunnel_public_host: "gate.example.com".into(),
        },
        hosts: Hosts {
            telemt: ("proxy.example.com", 443),
            naive: "naive.example.com",
            amneziawg: "awg.example.com",
            trusttunnel: "gate.example.com",
        },
        versions: StaticVersions { versions: Some(status["versions"].clone()), host: Some(status["host"].clone()) },
        now: 1_793_005_890.0,
    })
}

#[tokio::test]
async fn the_recorded_wire_replays_byte_for_byte() {
    let fleet = golden("fleet/fleet.json");
    let node = replay_node(&fleet);
    let wire = fleet["wire"].as_array().unwrap();
    assert_eq!(wire.len(), 38);
    let mut accepted = Vec::new();
    for (index, exchange) in wire.iter().enumerate() {
        let request = &exchange["request"];
        let path = request["url"].as_str().unwrap().strip_prefix("https://node.example").unwrap();
        let want_status = exchange["response"]["status"].as_u64().unwrap() as u16;
        let want_body = exchange["response"]["body"]["text"].as_str().unwrap();
        let got = match (request["method"].as_str().unwrap(), path) {
            ("GET", "/api/fleet/v2/identity") => render(node.node.identity().await.map(|body| (200, body))),
            ("GET", "/api/fleet/v2/status") => render(node.node.status().await.map(|body| (200, body))),
            ("GET", "/api/fleet/v2/inventory") => render(node.node.inventory().await.map(|body| (200, body))),
            ("PUT", "/api/fleet/v2/generation") => {
                let answer: Value = serde_json::from_str(want_body).unwrap();
                node.clock.set(answer["observed"]["reported_at"].as_f64().unwrap());
                let body: Value = serde_json::from_str(request["body"]["text"].as_str().unwrap()).unwrap();
                accepted.push(PushRequest::validate_body(&body).unwrap());
                push(&node, &body).await
            }
            other => panic!("unexpected exchange {other:?}"),
        };
        assert_eq!(got, (want_status, want_body.to_string()), "exchange {index}: {path}");
    }
    assert_eq!(accepted.len(), 5);

    // What the node stored: pydantic's document dump and the digest, per generation.
    let stored = support::table(&node.database, "SELECT * FROM managed_generations ORDER BY generation");
    let recorded = fleet["managed_generations"].as_array().unwrap();
    assert_eq!(stored.len(), recorded.len());
    for (ours, theirs) in stored.iter().zip(recorded) {
        for key in ["generation", "digest", "master_guid", "document_json", "state"] {
            assert_eq!(ours[key], theirs[key], "managed_generations.{key}");
        }
    }
    let stored = support::table(&node.database, "SELECT * FROM managed_resources ORDER BY protocol, runtime_username");
    let recorded = fleet["managed_resources"].as_array().unwrap();
    assert_eq!(stored.len(), recorded.len());
    for (ours, theirs) in stored.iter().zip(recorded) {
        for key in [
            "protocol",
            "runtime_username",
            "ref",
            "credential_ref",
            "generation",
            "state",
            "last_error",
            "revision",
            "learned_json",
        ] {
            assert_eq!(ours[key], theirs[key], "managed_resources.{key}");
        }
    }

    // The audit details of `fleet.generation.accept` (the route writes them; the bytes are these).
    let audit = golden("audit/audit.json");
    let rows: Vec<&Value> = audit["fleet-node"]["audit_log"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["action"] == "fleet.generation.accept")
        .collect();
    assert_eq!(rows.len(), accepted.len());
    for (row, request) in rows.iter().zip(&accepted) {
        let detail = panel_fleet::node::service::Accepted {
            generation: request.generation.generation,
            digest: request.generation.canonical_digest(),
            resources: request.generation.resources.len(),
        }
        .audit_detail();
        assert_eq!(row["target"], request.generation.generation.to_string());
        assert_eq!(row["detail_json"].as_str().unwrap(), panel_secrets::audit::detail_json(Some(&detail)));
    }

    // The central's view of the same generations: content digests agree with the node's documents.
    for (row, request) in fleet["desired_generations"].as_array().unwrap().iter().zip(&accepted) {
        assert_eq!(row["digest"].as_str().unwrap(), request.generation.canonical_digest());
        assert_eq!(row["content_digest"].as_str().unwrap(), request.generation.content_digest());
    }
}

#[tokio::test]
async fn node_side_refusals_answer_the_recorded_bodies() {
    let errors = golden("errors/error_bodies.json");
    let exchanges: Vec<&Value> = errors
        .as_array()
        .unwrap()
        .iter()
        .filter(|item| item["name"].as_str().unwrap().starts_with("fleet-node:"))
        .collect();
    let identity = exchanges.iter().find(|item| item["name"] == "fleet-node:identity").unwrap();
    let identity: Value = serde_json::from_str(identity["response"]["body"]["text"].as_str().unwrap()).unwrap();
    let node = Node::new(NodeOptions {
        guid: identity["guid"].as_str().unwrap().into(),
        now: 1_793_005_898.0,
        ..NodeOptions::default()
    });
    let mut checked = 0;
    for item in exchanges {
        let name = item["name"].as_str().unwrap();
        let want = (
            item["response"]["status"].as_u64().unwrap() as u16,
            item["response"]["body"]["text"].as_str().unwrap().to_string(),
        );
        let got = match name {
            "fleet-node:guid-mismatch"
            | "fleet-node:accept"
            | "fleet-node:stale-generation"
            | "fleet-node:digest-conflict"
            | "fleet-node:foreign-master"
            | "fleet-node:extra-field" => {
                let body: Value = serde_json::from_str(item["request"]["body"]["text"].as_str().unwrap()).unwrap();
                push(&node, &body).await
            }
            "fleet-node:observed" => render(node.node.observed().await.map(|body| (200, body))),
            // Authentication (WP4's gate) and the warming-up meters are covered by the HTTP tests.
            _ => continue,
        };
        assert_eq!(got, want, "{name}");
        checked += 1;
    }
    assert_eq!(checked, 7);
}
