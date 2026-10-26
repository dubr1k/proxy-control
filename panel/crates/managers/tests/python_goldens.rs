//! Replays every case recorded from the Python clients (`fixtures/python-clients.json`, made by
//! `fixtures/record_python.py` on ams-test) against the Rust clients: the same canned answer must
//! give the same outcome (value, or error class/message/status/code), and the request must be the
//! same bytes apart from the transport headers that differ by design (DIFFERENCES.md).

mod common;

use std::time::Duration;

use base64::Engine as _;
use common::{FakeServer, ParsedRequest, Reply};
use panel_managers::{
    AmneziawgClient, LifecycleAction, ManagerError, MieruClient, NaiveClient, TelemtClient, TelemtError,
    TrusttunnelClient, VersionAgentError, VersionClient, XrayRouterClient,
};
use serde_json::{json, Value};

const TOKEN: &str = "synthetic-token-0123456789abcdef0123456789";
const TELEMT_AUTH: &str = "Bearer synthetic-telemt-token-0123456789abcdef";
const TIMEOUT: Duration = Duration::from_millis(500);

fn cases() -> Vec<Value> {
    let text = include_str!("fixtures/python-clients.json");
    let fixture: Value = serde_json::from_str(text).unwrap();
    fixture["cases"].as_array().unwrap().clone()
}

fn manager_error(error: ManagerError) -> Value {
    json!({"kind": "error", "class": error.manager.error_class(), "message": error.message,
           "status_code": error.status_code, "code": error.code})
}

fn telemt_error(error: TelemtError) -> Value {
    let class = if error.indeterminate { "TelemtIndeterminate" } else { "TelemtError" };
    json!({"kind": "error", "class": class, "message": error.message, "status_code": error.status_code, "code": null})
}

fn agent_error(error: VersionAgentError) -> Value {
    json!({"kind": "error", "class": "VersionAgentError", "message": error.message,
           "status_code": error.status_code, "code": null})
}

fn ok(value: Value) -> Value {
    json!({"kind": "ok", "value": value})
}

fn managed(result: Result<Value, ManagerError>) -> Value {
    result.map(ok).unwrap_or_else(manager_error)
}

fn telemt(result: Result<Value, TelemtError>) -> Value {
    result.map(ok).unwrap_or_else(telemt_error)
}

fn agent(result: Result<Value, VersionAgentError>) -> Value {
    result.map(ok).unwrap_or_else(agent_error)
}

/// Calls `client.method(*args, **kwargs)` on the Rust twin.
async fn dispatch(client: &str, method: &str, args: &[Value], kwargs: &Value, socket: &str, url: &str) -> Value {
    let s = |index: usize| args[index].as_str().unwrap();
    let i = |index: usize| args[index].as_i64();
    let k = |name: &str| kwargs.get(name).and_then(Value::as_str);
    match client {
        "naive" => {
            let c = NaiveClient::new(socket, TOKEN).with_timeout(TIMEOUT);
            managed(match method {
                "health" => c.health().await,
                "list_users" => c.list_users().await,
                "traffic" => c.traffic().await,
                "create" => c.create(s(0), i(1), k("password"), k("operation_id")).await,
                "reveal" => c.reveal(s(0)).await,
                "rotate" => c.rotate(s(0), k("password"), k("operation_id")).await,
                "set_enabled" => c.set_enabled(s(0), args[1].as_bool().unwrap()).await,
                "set_quota" => c.set_quota(s(0), i(1)).await,
                "delete" => c.delete(s(0)).await,
                "reset_traffic" => c.reset_traffic(s(0)).await,
                "egress" => c.egress().await,
                "egress_plan" => c.egress_plan(s(0), &args[1]).await,
                "egress_apply" => c.egress_apply(s(0), &args[1], s(2)).await,
                "egress_rollback" => c.egress_rollback(s(0)).await,
                "lanes" => c.lanes().await,
                "set_lanes" => c.set_lanes(&args[0]).await,
                other => panic!("naive.{other}"),
            })
        }
        "mieru" => {
            let c = MieruClient::new(socket, TOKEN).with_timeout(TIMEOUT);
            managed(match method {
                "health" => c.health().await,
                "list_users" => c.list_users().await,
                "metrics" => c.metrics().await,
                "traffic" => c.traffic().await,
                "lifecycle" => c.lifecycle(LifecycleAction::parse(s(0)).unwrap()).await,
                "create" => c.create(&args[0]).await,
                "set_quotas" => c.set_quotas(s(0), &args[1]).await,
                "operation" => c.operation(s(0), s(1), s(2)).await,
                "rotate" => c.rotate(s(0), s(1), k("password"), k("operation_id")).await,
                "delete" => c.delete(s(0), s(1)).await,
                "reset_metrics" => c.reset_metrics(s(0)).await,
                "egress" => c.egress().await,
                "egress_plan" => c.egress_plan(s(0), &args[1]).await,
                "egress_apply" => c.egress_apply(s(0), &args[1], s(2)).await,
                "egress_rollback" => c.egress_rollback(s(0)).await,
                "lanes" => c.lanes().await,
                "set_lanes" => c.set_lanes(&args[0]).await,
                other => panic!("mieru.{other}"),
            })
        }
        "amneziawg" => {
            let c = AmneziawgClient::new(socket, TOKEN).with_timeout(TIMEOUT);
            managed(match method {
                "health" => c.health().await,
                "instances" => c.instances().await,
                "peers" => c.peers().await,
                "create_peer" => c.create_peer(&args[0]).await,
                "peer_state" => c.peer_state(s(0), s(1)).await,
                "rotate_peer" => c.rotate_peer(s(0), &args[1]).await,
                "delete_peer" => c.delete_peer(s(0)).await,
                "egress" => c.egress().await,
                "egress_plan" => c.egress_plan(s(0), &args[1]).await,
                "egress_apply" => c.egress_apply(s(0), &args[1], s(2)).await,
                "egress_rollback" => c.egress_rollback(s(0)).await,
                other => panic!("amneziawg.{other}"),
            })
        }
        "trusttunnel" => {
            let c = TrusttunnelClient::new(socket, TOKEN).with_timeout(TIMEOUT);
            managed(match method {
                "health" => c.health().await,
                "endpoint" => c.endpoint().await,
                "clients" => c.clients().await,
                "create_client" => c.create_client(&args[0]).await,
                "client_state" => c.client_state(s(0), s(1)).await,
                "rotate_client" => c.rotate_client(s(0), &args[1]).await,
                "delete_client" => c.delete_client(s(0)).await,
                "egress" => c.egress().await,
                "egress_plan" => c.egress_plan(&args[0]).await,
                "egress_apply" => c.egress_apply(&args[0]).await,
                "egress_rollback" => c.egress_rollback().await,
                other => panic!("trusttunnel.{other}"),
            })
        }
        "xray_router" => {
            let c = XrayRouterClient::new(socket, TOKEN).with_timeout(TIMEOUT);
            managed(match method {
                "status" => c.status().await,
                "egress" => c.egress(s(0)).await,
                "egress_plan" => c.egress_plan(s(0), s(1), &args[2]).await,
                "egress_apply" => c.egress_apply(s(0), s(1), &args[2], s(3)).await,
                "egress_rollback" => c.egress_rollback(s(0), s(1)).await,
                "lanes" => c.lanes(s(0)).await,
                "lane_issue" => c.lane_issue(s(0), s(1)).await,
                "lane_forget" => c.lane_forget(s(0), s(1)).await,
                "relay" => c.relay().await,
                "ingress" => c.ingress(s(0)).await,
                "relay_enable" => c.relay_enable(s(0), i(1).unwrap()).await,
                "relay_disable" => c.relay_disable().await,
                "geodata" => c.geodata().await,
                "geodata_codes" => c.geodata_codes().await,
                "geodata_settings" => c.geodata_settings(&args[0]).await,
                "geodata_update" => c.geodata_update().await,
                "geodata_restore" => c.geodata_restore().await,
                "exit_test" => c.exit_test(&args[0]).await,
                "relay_set_accounts" => c.relay_set_accounts(&args[0]).await,
                other => panic!("xray_router.{other}"),
            })
        }
        "versions" => {
            let c = VersionClient::new(socket).with_timeout(TIMEOUT);
            match method {
                "list_versions" => agent(c.list_versions().await),
                "host" => agent(c.host().await),
                "metrics" => ok(c.metrics().await.unwrap_or(Value::Null)),
                "check" => agent(c.check().await),
                "rebuild_managers" => agent(c.rebuild_managers().await),
                "update" => agent(c.update(s(0), s(1), args[2].as_str()).await),
                other => panic!("versions.{other}"),
            }
        }
        "telemt" => {
            let c = TelemtClient::with_timeout(url, TELEMT_AUTH, TIMEOUT);
            let pair =
                |result: Result<(Value, Value), TelemtError>| telemt(result.map(|(data, rev)| json!([data, rev])));
            match method {
                "list_users" => telemt(c.list_users().await),
                "create_user" => telemt(c.create_user(s(0), args.get(1).and_then(Value::as_str)).await),
                "delete_user" => telemt(c.delete_user(s(0)).await),
                "set_enabled" => telemt(c.set_enabled(s(0), args[1].as_bool().unwrap()).await),
                "rotate" => telemt(c.rotate(s(0), args.get(1).and_then(Value::as_str)).await),
                "update_user" => telemt(c.update_user(s(0), &args[1]).await),
                "reset_quota" => telemt(c.reset_quota(s(0)).await),
                "health" => telemt(c.health().await),
                "stats" => telemt(c.stats().await),
                "connections" => telemt(c.connections().await),
                "active_ips" => telemt(c.active_ips().await),
                "quota_stats" => telemt(c.quota_stats().await),
                "config" => pair(c.config().await),
                "patch_config" => pair(c.patch_config(&args[0], s(1)).await),
                "reload" => telemt(c.reload(s(0)).await),
                "reload_status" => telemt(c.reload_status(i(0).unwrap()).await),
                "current_access" => telemt(
                    c.current_access(s(0)).await.map(|access| access.map(|a| a.to_value()).unwrap_or(Value::Null)),
                ),
                other => panic!("telemt.{other}"),
            }
        }
        other => panic!("client {other}"),
    }
}

fn reply_of(spec: &Value) -> Reply {
    if spec["close"] == json!(true) {
        return Reply::Close;
    }
    if spec["hang"] == json!(true) {
        return Reply::Hang(Duration::from_millis(1500));
    }
    let body = spec["body"].as_str().unwrap_or("").as_bytes().to_vec();
    Reply::Answer(spec["status"].as_u64().unwrap() as u16, body)
}

/// The headers that carry meaning to a manager: everything but the transport's own (`Host`,
/// `Accept*`, `Connection`, `User-Agent`), with a zero `Content-Length` on an empty body dropped.
fn semantic(request: &ParsedRequest) -> Vec<(String, String)> {
    let mut headers: Vec<(String, String)> = request
        .headers
        .iter()
        .filter(|(name, _)| {
            !matches!(name.as_str(), "host" | "accept" | "accept-encoding" | "connection" | "user-agent")
        })
        .filter(|(name, value)| !(name == "content-length" && value == "0" && request.body.is_empty()))
        .cloned()
        .collect();
    headers.sort();
    headers
}

/// Python crashes (`AttributeError`, a 500) on these answers; Rust answers the client's own
/// "invalid response" error instead (DIFFERENCES.md).
fn python_crash_expectation(case: &Value) -> Value {
    let class = case["client"].as_str().unwrap();
    let (error_class, message) = match class {
        "amneziawg" => ("AmneziawgError", "Invalid AmneziaWG manager response"),
        "trusttunnel" => ("TrusttunnelError", "Invalid TrustTunnel manager response"),
        "telemt" => ("TelemtError", "Invalid Telemt API response"),
        other => panic!("unexpected Python crash for {other}: {case}"),
    };
    json!({"kind": "error", "class": error_class, "message": message, "status_code": 502, "code": null})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_python_case_gives_the_same_outcome_and_request() {
    let uds = FakeServer::unix();
    let tcp = FakeServer::tcp();
    let missing = uds.socket().with_file_name("missing.sock");
    let mut compared_requests = 0;
    let cases = cases();
    assert!(cases.len() > 300, "the fixture holds every case");
    for case in &cases {
        let client = case["client"].as_str().unwrap();
        let method = case["method"].as_str().unwrap();
        let args = case["args"].as_array().unwrap();
        let (socket, url) = match &case["reply"] {
            Value::String(kind) if kind == "missing" => (missing.to_str().unwrap().to_string(), tcp.url()),
            Value::String(kind) if kind == "refused" => (String::new(), "http://127.0.0.1:1".to_string()),
            spec => {
                uds.always(reply_of(spec));
                tcp.always(reply_of(spec));
                (uds.socket().to_str().unwrap().to_string(), tcp.url())
            }
        };
        uds.take();
        tcp.take();
        let outcome = dispatch(client, method, args, &case["kwargs"], &socket, &url).await;
        let expected = match case["outcome"]["class"].as_str() {
            Some("AttributeError" | "TypeError") => python_crash_expectation(case),
            _ => case["outcome"].clone(),
        };
        assert_eq!(outcome, expected, "outcome of {client}.{method} on {}", case["reply"]);
        let python: Vec<ParsedRequest> = case["requests"]
            .as_array()
            .unwrap()
            .iter()
            .map(|raw| {
                ParsedRequest::parse(&base64::engine::general_purpose::STANDARD.decode(raw.as_str().unwrap()).unwrap())
            })
            .collect();
        let rust: Vec<ParsedRequest> =
            if client == "telemt" { tcp.take() } else { uds.take() }.iter().map(|r| r.parsed()).collect();
        assert_eq!(python.len(), rust.len(), "requests of {client}.{method}");
        for (python, rust) in python.iter().zip(&rust) {
            assert_eq!(python.line, rust.line, "{client}.{method}");
            assert_eq!(python.body, rust.body, "body of {client}.{method}");
            assert_eq!(semantic(python), semantic(rust), "headers of {client}.{method}");
            compared_requests += 1;
        }
    }
    assert!(compared_requests > 250, "{compared_requests} requests compared");
}

/// The transport headers that differ: Python's httpx names the dummy base host and sends its own
/// `Accept`, `Accept-Encoding`, `Connection: keep-alive` and `User-Agent`; `pc_common` sends
/// `Host: localhost` and `Connection: close`. A bodyless POST carries `Content-Length: 0` from
/// httpx and no length from `pc_common` (a manager reads both as an empty body).
#[tokio::test]
async fn transport_headers_differ_only_as_documented() {
    let uds = FakeServer::unix();
    uds.always(Reply::json(200, json!({})));
    TrusttunnelClient::new(uds.socket(), TOKEN).egress_rollback().await.unwrap();
    let request = uds.take().remove(0).parsed();
    assert_eq!(request.line, "POST /v1/egress/rollback HTTP/1.1");
    assert_eq!(request.header("host"), Some("localhost"));
    assert_eq!(request.header("connection"), Some("close"));
    assert_eq!(request.header("content-length"), None);
    assert_eq!(request.header("x-trusttunnel-token"), Some(TOKEN));
}
