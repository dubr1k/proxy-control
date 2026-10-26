//! The Python unit tests of the client modules, ported (name minus `test_`; the Python file is in
//! each module's doc line), plus the Telemt egress journal against the Python-written golden.

mod common;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{FakeServer, Reply, TempDir};
use panel_managers::{
    AmneziawgClient, LifecycleAction, MieruClient, NaiveClient, TelemtClient, TelemtEgressJournal, TrusttunnelClient,
    VersionClient, XrayRouterClient, EGRESS_REASON_CODES,
};
use serde_json::{json, Value};

/// `panel/tests/test_local_http.py` — httpx built a CA context per transport; the Rust clients hold
/// none for Unix sockets and the Telemt client builds its TLS configuration once.
mod local_http {
    use super::*;

    #[tokio::test]
    async fn every_manager_client_reuses_one_tls_context() {
        let server = FakeServer::unix();
        server.always(Reply::Answer(200, b"{}".to_vec()));
        let path = server.socket();
        for _ in 0..3 {
            assert_eq!(VersionClient::new(path).request("GET", "/v1/health", None, None).await.unwrap(), json!({}));
            for answer in [
                MieruClient::new(path, "t").raw().request("GET", "/v1/health", None, None).await,
                NaiveClient::new(path, "t").raw().request("GET", "/v1/health", None, None).await,
                AmneziawgClient::new(path, "t").raw().request("GET", "/v1/health", None, None).await,
                TrusttunnelClient::new(path, "t").raw().request("GET", "/v1/health", None, None).await,
                XrayRouterClient::new(path, "t").raw().request("GET", "/v1/health", None, None).await,
            ] {
                assert_eq!(answer.unwrap(), json!({}));
            }
        }
        assert_eq!(server.take().len(), 18);
    }

    #[tokio::test]
    async fn the_telemt_client_reuses_it_over_tcp() {
        let server = FakeServer::tcp();
        server.always(Reply::Answer(200, b"{}".to_vec()));
        let client = TelemtClient::new(&server.url(), "Bearer t");
        for _ in 0..3 {
            // The body is not Telemt's envelope; the transport is the point.
            let error = client.request(reqwest::Method::GET, "/v1/users", None, None).await.unwrap_err();
            assert_eq!(error.message, "Telemt API rejected request");
        }
        assert_eq!(server.take().len(), 3);
    }

    /// The Telemt client verifies the peer: a self-signed certificate is refused before any request
    /// byte, as a plain (retryable) failure.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_shared_context_still_verifies_peers() {
        let dir = TempDir::new("wp5-tls");
        let status = std::process::Command::new("openssl")
            .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=127.0.0.1"])
            .args(["-addext", "subjectAltName=IP:127.0.0.1", "-keyout", "key.pem", "-out", "cert.pem"])
            .current_dir(dir.path())
            .output()
            .expect("openssl is installed");
        assert!(status.status.success());
        use rustls::pki_types::pem::PemObject;
        let certs: Vec<_> = rustls::pki_types::CertificateDer::pem_file_iter(dir.path().join("cert.pem"))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let key = rustls::pki_types::PrivateKeyDer::from_pem_file(dir.path().join("key.pem")).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let plaintext = Arc::new(AtomicBool::new(false));
        let seen = plaintext.clone();
        std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let connection = rustls::ServerConnection::new(Arc::new(config)).unwrap();
            let mut tls = rustls::StreamOwned::new(connection, tcp);
            let mut buffer = [0u8; 16];
            if std::io::Read::read(&mut tls, &mut buffer).is_ok_and(|n| n > 0) {
                seen.store(true, Ordering::SeqCst);
            }
        });
        let client = TelemtClient::new(&format!("https://127.0.0.1:{port}"), "Bearer t");
        let error = client.list_users().await.unwrap_err();
        assert_eq!((error.message.as_str(), error.indeterminate), ("Telemt API unavailable", false));
        std::thread::sleep(Duration::from_millis(100));
        assert!(!plaintext.load(Ordering::SeqCst), "no request byte reached an unverified peer");
    }
}

/// `panel/tests/test_xray_router_client.py`
#[tokio::test]
async fn client_speaks_the_router_routes_and_keeps_the_bounded_codes() {
    let warp = json!({"schema": 1, "default": {"action": "egress", "egress": "warp"}, "rules": []});
    let server = FakeServer::unix();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = seen.clone();
    server.respond(move |request| {
        let path = request.line.split(' ').nth(1).unwrap().to_string();
        record.lock().unwrap().push(request.header("x-xray-router-token").unwrap_or("").to_string());
        match path.as_str() {
            "/v1/status" => Reply::json(200, json!({"running": {"generation": 1}})),
            "/v1/egress/naive/apply" => Reply::json(422, json!({"detail": "xray refused", "code": "geosite_unknown"})),
            "/v1/egress/naive/rollback" => Reply::json(409, json!({"detail": "nope", "code": "not-a-known-code"})),
            "/v1/egress/mieru" => Reply::json(503, json!({"detail": "digest", "code": "artifact_mismatch"})),
            _ => Reply::json(200, json!({"revision": "r"})),
        }
    });
    let token = "t".repeat(40);
    let client = XrayRouterClient::new(server.socket(), token.clone());
    assert_eq!(client.status().await.unwrap()["running"]["generation"], 1);
    assert_eq!(client.egress("naive").await.unwrap()["revision"], "r");
    assert_eq!(client.egress_plan("naive", "r", &warp).await.unwrap()["revision"], "r");
    let caught = client.egress_apply("naive", "r", &warp, "op-1").await.unwrap_err();
    assert_eq!((caught.status_code, caught.code.as_deref()), (422, Some("geosite_unknown")));
    let caught = client.egress_rollback("naive", "r").await.unwrap_err();
    assert_eq!((caught.status_code, caught.code.as_deref()), (409, None));
    let caught = client.egress("mieru").await.unwrap_err();
    assert_eq!((caught.status_code, caught.code.as_deref()), (503, Some("artifact_mismatch")));
    assert!(seen.lock().unwrap().iter().all(|seen| *seen == token));
    for code in ["geosite_unknown", "geoip_unknown", "artifact_mismatch"] {
        assert!(EGRESS_REASON_CODES.contains(&code));
    }
}

fn telemt_server(handler: impl FnMut(&common::ParsedRequest) -> Reply + Send + 'static) -> (FakeServer, TelemtClient) {
    let server = FakeServer::tcp();
    server.respond(handler);
    let client = TelemtClient::new(&server.url(), "Bearer t");
    (server, client)
}

/// `panel/tests/test_telemt_recovery.py`
mod telemt_recovery {
    use super::*;

    #[tokio::test]
    async fn a_request_that_never_left_is_a_plain_failure_not_indeterminate() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener); // refused
        let failure =
            TelemtClient::new(&format!("http://127.0.0.1:{port}"), "Bearer t").list_users().await.unwrap_err();
        // A connection that was never established sent nothing: a retry is safe.
        assert!(!failure.indeterminate);
        assert_eq!(failure.message, "Telemt API unavailable");
    }

    #[tokio::test]
    async fn a_reply_lost_after_the_request_was_sent_is_indeterminate() {
        let server = FakeServer::tcp();
        server.always(Reply::Hang(Duration::from_millis(600)));
        let client = TelemtClient::with_timeout(&server.url(), "Bearer t", Duration::from_millis(200));
        assert!(client.create_user("alice", None).await.unwrap_err().indeterminate);
        server.always(Reply::Close);
        assert!(client.create_user("alice", None).await.unwrap_err().indeterminate);
    }

    #[tokio::test]
    async fn current_access_reads_the_live_link_from_the_user_listing() {
        let link = format!("tg://proxy?server=proxy.example.com&port=443&secret=ee{}", "ab".repeat(16));
        let listing = json!({"ok": true, "data": [{"username": "alice", "links": {"tls": [link]}}]});
        let (server, client) = telemt_server(move |request| {
            assert_eq!(request.line, "GET /v1/users HTTP/1.1");
            Reply::json(200, listing.clone())
        });
        let access = client.current_access("alice").await.unwrap().unwrap();
        // The endpoint travels with the link: the panel has no other source for it.
        assert_eq!(
            access.to_value(),
            json!({"link": link, "secret": format!("ee{}", "ab".repeat(16)), "server": "proxy.example.com", "port": 443})
        );
        assert_eq!(server.take().len(), 1);
    }
}

/// `panel/tests/test_amneziawg.py`
mod amneziawg {
    use super::*;

    #[tokio::test]
    async fn the_real_client_speaks_the_manager_contract() {
        let server = FakeServer::unix();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let record = calls.clone();
        server.respond(move |request| {
            let mut parts = request.line.split(' ');
            let (method, path) = (parts.next().unwrap().to_string(), parts.next().unwrap().to_string());
            record.lock().unwrap().push((
                method.clone(),
                path.clone(),
                request.header("x-awg-token").map(str::to_string),
            ));
            if path == "/v1/peers/ghost/enable" {
                return Reply::json(404, json!({"detail": "no", "code": "not_found"}));
            }
            if method == "DELETE" {
                return Reply::Answer(204, Vec::new());
            }
            Reply::json(200, json!({"peers": [], "instances": []}))
        });
        let client = AmneziawgClient::new(server.socket(), "tok");
        assert_eq!(client.peers().await.unwrap(), json!([]));
        assert_eq!(client.instances().await.unwrap(), json!([]));
        assert_eq!(client.delete_peer("alice-awg20").await.unwrap(), Value::Null);
        let error = client.peer_state("ghost", "enable").await.unwrap_err();
        assert_eq!((error.status_code, error.code.as_deref()), (404, Some("not_found")));
        let calls = calls.lock().unwrap();
        assert!(calls.iter().all(|(_, _, token)| token.as_deref() == Some("tok")));
        assert!(calls.contains(&("DELETE".into(), "/v1/peers/alice-awg20".into(), Some("tok".into()))));
    }
}

/// `panel/tests/test_trusttunnel.py`
mod trusttunnel {
    use super::*;

    #[tokio::test]
    async fn the_real_client_speaks_the_manager_contract() {
        let server = FakeServer::unix();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let record = calls.clone();
        server.respond(move |request| {
            let mut parts = request.line.split(' ');
            let (method, path) = (parts.next().unwrap().to_string(), parts.next().unwrap().to_string());
            record.lock().unwrap().push((
                method.clone(),
                path.clone(),
                request.header("x-trusttunnel-token").map(str::to_string),
            ));
            if path == "/v1/clients/ghost/enable" {
                return Reply::json(404, json!({"detail": "no", "code": "not_found"}));
            }
            if method == "DELETE" {
                return Reply::Answer(204, Vec::new());
            }
            if path == "/v1/clients" && method == "POST" {
                return Reply::json(409, json!({"detail": "x", "code": "exists"}));
            }
            Reply::json(200, json!({"clients": []}))
        });
        let client = TrusttunnelClient::new(server.socket(), "tok");
        assert_eq!(client.clients().await.unwrap(), json!([]));
        client.egress_apply(&json!({"mode": "direct"})).await.unwrap();
        client.egress_rollback().await.unwrap();
        client.delete_client("alice").await.unwrap();
        let missing = client.client_state("ghost", "enable").await.unwrap_err();
        assert_eq!((missing.status_code, missing.code.as_deref()), (404, Some("not_found")));
        let exists =
            client.create_client(&json!({"operation_id": "o", "username": "a", "password": "p"})).await.unwrap_err();
        assert_eq!((exists.status_code, exists.code.as_deref()), (409, Some("exists")));
        let calls = calls.lock().unwrap();
        assert!(calls.iter().all(|(_, _, token)| token.as_deref() == Some("tok")));
        for expected in [("POST", "/v1/egress/apply"), ("POST", "/v1/egress/rollback"), ("DELETE", "/v1/clients/alice")]
        {
            assert!(calls.contains(&(expected.0.into(), expected.1.into(), Some("tok".into()))), "{expected:?}");
        }
    }
}

/// `panel/tests/test_naive_management.py`
#[tokio::test]
async fn naive_adapter_accepts_empty_204_delete_response() {
    let server = FakeServer::unix();
    server.respond(|request| {
        assert!(request.line.starts_with("DELETE "));
        Reply::Answer(204, Vec::new())
    });
    let adapter = NaiveClient::new(server.socket(), "internal-token");
    assert_eq!(adapter.delete("phone").await.unwrap(), Value::Null);
}

/// `panel/tests/test_mieru_management.py`
mod mieru_management {
    use super::*;

    #[tokio::test]
    async fn mieru_client_reads_the_manager_traffic_route() {
        let server = FakeServer::unix();
        server.always(Reply::json(200, json!({"users": [{"username": "a", "upload_bytes": 1, "download_bytes": 2}]})));
        let client = MieruClient::new(server.socket(), "token");
        assert_eq!(client.traffic().await.unwrap()["users"][0]["download_bytes"], 2);
        assert_eq!(server.take()[0].parsed().line, "GET /v1/traffic HTTP/1.1");
    }

    #[tokio::test]
    async fn mieru_client_sanitizes_manager_errors() {
        let server = FakeServer::unix();
        server.always(Reply::Answer(409, br#"{"detail":"hash aaaa password secret"}"#.to_vec()));
        let error = MieruClient::new(server.socket(), "token").list_users().await.unwrap_err();
        assert!(error.to_string().contains("manager rejected request"));
        assert!(!error.to_string().contains("password"));
    }

    #[tokio::test]
    async fn mieru_client_lifecycle_uses_fixed_allowlisted_path_and_empty_body() {
        let server = FakeServer::unix();
        server.always(Reply::json(200, json!({"ready": true, "status": "running", "revision": "rev-1"})));
        let client = MieruClient::new(server.socket(), "x".repeat(32));
        assert_eq!(client.lifecycle(LifecycleAction::Restart).await.unwrap()["ready"], true);
        let request = server.take().remove(0).parsed();
        assert_eq!((request.line.as_str(), request.json()), ("POST /v1/lifecycle/restart HTTP/1.1", json!({})));
        let refused = LifecycleAction::parse("reload").unwrap_err();
        assert!(refused.to_string().contains("lifecycle"));
    }
}

/// `panel/tests/test_egress_adapters.py` (parametrised over the naive and mieru clients)
mod egress_adapters {
    use super::*;

    fn handler(header: &'static str) -> impl FnMut(&common::ParsedRequest) -> Reply + Send + 'static {
        move |request| {
            assert_eq!(request.header(header), Some("internal-token"));
            let path = request.line.split(' ').nth(1).unwrap().to_string();
            if path == "/v1/egress" {
                Reply::json(200, json!({"revision": "r1"}))
            } else if path.ends_with("/rollback") {
                Reply::json(503, json!({"detail": "x", "code": "manual_intervention_required"}))
            } else if path.ends_with("/plan") {
                Reply::json(409, json!({"detail": "x", "code": "egress_conflict"}))
            } else if path.ends_with("/apply") {
                Reply::json(409, json!({"detail": "x", "code": "some_new_code"}))
            } else {
                Reply::Answer(404, Vec::new())
            }
        }
    }

    fn check_bodies(server: &FakeServer) {
        let bodies: Vec<(String, Vec<u8>)> = server
            .take()
            .iter()
            .map(|r| r.parsed())
            .map(|r| (r.line.split(' ').nth(1).unwrap().to_string(), r.body))
            .collect();
        let body = |path: &str| bodies.iter().find(|(p, _)| p == path).unwrap().1.clone();
        assert!(String::from_utf8(body("/v1/egress/plan")).unwrap().contains(r#""expected_revision":"r1""#));
        assert!(String::from_utf8(body("/v1/egress/apply")).unwrap().contains(r#""operation_id":"op-1""#));
        for code in [
            "egress_conflict",
            "egress_invalid",
            "egress_unreachable",
            "egress_readback_mismatch",
            "manual_intervention_required",
            "egress_no_previous",
        ] {
            assert!(EGRESS_REASON_CODES.contains(&code));
        }
    }

    #[tokio::test]
    async fn manager_clients_speak_the_egress_routes_and_keep_the_bounded_codes_naive() {
        let server = FakeServer::unix();
        server.respond(handler("x-naive-token"));
        let client = NaiveClient::new(server.socket(), "internal-token");
        let document = json!({"schema": 1});
        assert_eq!(client.egress().await.unwrap(), json!({"revision": "r1"}));
        let failure = client.egress_plan("r1", &document).await.unwrap_err();
        assert_eq!((failure.status_code, failure.code.as_deref()), (409, Some("egress_conflict")));
        let failure = client.egress_apply("r1", &document, "op-1").await.unwrap_err();
        assert_eq!((failure.status_code, failure.code), (409, None)); // unknown codes never reach panel copy
        let failure = client.egress_rollback("r1").await.unwrap_err();
        assert_eq!((failure.status_code, failure.code.as_deref()), (502, Some("manual_intervention_required")));
        check_bodies(&server);
    }

    #[tokio::test]
    async fn manager_clients_speak_the_egress_routes_and_keep_the_bounded_codes_mieru() {
        let server = FakeServer::unix();
        server.respond(handler("x-mieru-token"));
        let client = MieruClient::new(server.socket(), "internal-token");
        let document = json!({"schema": 1});
        assert_eq!(client.egress().await.unwrap(), json!({"revision": "r1"}));
        let failure = client.egress_plan("r1", &document).await.unwrap_err();
        assert_eq!((failure.status_code, failure.code.as_deref()), (409, Some("egress_conflict")));
        let failure = client.egress_apply("r1", &document, "op-1").await.unwrap_err();
        assert_eq!((failure.status_code, failure.code), (409, None));
        let failure = client.egress_rollback("r1").await.unwrap_err();
        assert_eq!((failure.status_code, failure.code.as_deref()), (502, Some("manual_intervention_required")));
        check_bodies(&server);
    }
}

/// `panel/tests/test_access_enforcement.py`
#[tokio::test]
async fn telemt_batch_readback_observes_enable_disable_mutations() {
    let enabled = Arc::new(AtomicBool::new(true));
    let state = enabled.clone();
    let (_server, telemt) = telemt_server(move |request| {
        if request.line.starts_with("POST ") {
            state.store(false, Ordering::SeqCst);
        }
        Reply::json(200, json!({"ok": true, "data": [{"username": "alice", "enabled": state.load(Ordering::SeqCst)}]}))
    });
    let _batch = telemt.batch();
    assert_eq!(telemt.list_users().await.unwrap()[0]["enabled"], true);
    telemt.set_enabled("alice", false).await.unwrap();
    assert_eq!(telemt.list_users().await.unwrap()[0]["enabled"], false);
}

/// `panel/tests/test_fleet_v2_post_merge.py`
#[tokio::test]
async fn telemt_client_batches_inventory_reads_until_access_changes() {
    let users = Arc::new(Mutex::new(serde_json::Map::new()));
    for name in ["u1", "u2"] {
        let digit = &name[1..];
        users.lock().unwrap().insert(
            name.into(),
            json!({"username": name, "enabled": true,
                   "links": {"tls": [format!("tg://proxy?server=h&port=443&secret=ee{digit}{digit}")]}}),
        );
    }
    let reads = Arc::new(AtomicUsize::new(0));
    let (state, counter) = (users.clone(), reads.clone());
    let (_server, client) = telemt_server(move |request| {
        let mut parts = request.line.split(' ');
        let (method, path) = (parts.next().unwrap(), parts.next().unwrap());
        let mut users = state.lock().unwrap();
        if method == "GET" {
            counter.fetch_add(1, Ordering::SeqCst);
            return Reply::json(200, json!({"ok": true, "data": users.values().cloned().collect::<Vec<_>>()}));
        }
        let segments: Vec<&str> = path.split('/').collect();
        let row = users.get_mut(segments[3]).unwrap();
        let last = *segments.last().unwrap();
        if method == "PATCH" {
            for (key, value) in request.json().as_object().unwrap() {
                row[key] = value.clone();
            }
        } else if last == "enable" || last == "disable" {
            row["enabled"] = json!(last == "enable");
        } else if last == "rotate-secret" {
            row["links"]["tls"] = json!(["tg://proxy?server=h&port=443&secret=ee33"]);
        }
        Reply::json(200, json!({"ok": true, "data": {}}))
    });
    let assert_reads = |count: usize| assert_eq!(reads.load(Ordering::SeqCst), count);
    {
        let _batch = client.batch();
        client.list_users().await.unwrap(); // discover
        for name in ["u1", "u2", "u1", "u2"] {
            let digit = &name[1..];
            assert_eq!(
                client.current_access(name).await.unwrap().unwrap().secret.unwrap(),
                format!("ee{digit}{digit}")
            );
        }
        assert_reads(1); // read-only lookups still share one inventory
        for (index, (name, enabled)) in
            [("u1", false), ("u2", false), ("u1", true), ("u2", true)].into_iter().enumerate()
        {
            client.set_enabled(name, enabled).await.unwrap();
            let rows = client.list_users().await.unwrap();
            let row = rows.as_array().unwrap().iter().find(|row| row["username"] == name).unwrap().clone();
            assert_eq!(row["enabled"], enabled); // the real runtime state, not the pre-write cache
            client.current_access("u1").await.unwrap();
            client.current_access("u2").await.unwrap();
            assert_reads(index + 2); // exactly one fresh read after each mutation
        }
        client.update_user("u1", &json!({"max_tcp_conns": 3})).await.unwrap();
        let rows = client.list_users().await.unwrap();
        assert_eq!(rows.as_array().unwrap().iter().find(|row| row["username"] == "u1").unwrap()["max_tcp_conns"], 3);
        client.current_access("u1").await.unwrap();
        assert_reads(6);
        client.rotate("u1", None).await.unwrap(); // link mutations also invalidate the snapshot
        assert_eq!(client.current_access("u1").await.unwrap().unwrap().secret.as_deref(), Some("ee33"));
        client.current_access("u2").await.unwrap();
        assert_reads(7);
    }
    client.current_access("u2").await.unwrap(); // outside a batch every look-up reads
    assert_reads(8);
}

/// `panel/tests/test_users_adapter_ui.py`
mod users_adapter_ui {
    use super::*;

    #[tokio::test]
    async fn telemt_adapter_patches_limits_and_resets_quota() {
        let (server, telemt) =
            telemt_server(|_| Reply::json(200, json!({"ok": true, "data": {"username": "alice"}, "revision": "r"})));
        telemt.update_user("alice", &json!({"data_quota_bytes": 2048})).await.unwrap();
        telemt.reset_quota("alice").await.unwrap();
        let seen: Vec<_> = server.take().iter().map(|r| r.parsed()).collect();
        assert_eq!(seen[0].line, "PATCH /v1/users/alice HTTP/1.1");
        assert_eq!(seen[0].body, br#"{"data_quota_bytes":2048}"#);
        assert_eq!(seen[1].line, "POST /v1/users/alice/reset-quota HTTP/1.1");
    }

    #[tokio::test]
    async fn telemt_adapter_reads_3425_quota_stats_route() {
        let stats = json!({"users": [{"username": "alice", "data_quota_bytes": 2048, "used_bytes": 512,
                                       "last_reset_epoch_secs": 123}]});
        let answer = json!({"ok": true, "data": stats, "revision": "r"});
        let (server, telemt) = telemt_server(move |_| Reply::json(200, answer.clone()));
        assert_eq!(telemt.quota_stats().await.unwrap(), stats);
        let lines: Vec<_> = server.take().iter().map(|r| r.parsed().line).collect();
        assert_eq!(lines, ["GET /v1/stats/users/quota HTTP/1.1"]);
    }

    #[tokio::test]
    async fn telemt_adapter_sends_auth_and_maps_envelope() {
        let server = FakeServer::tcp();
        server.always(Reply::json(200, json!({"ok": true, "data": [{"username": "a"}], "revision": "r"})));
        let client = TelemtClient::new(&server.url(), "Bearer internal-token");
        assert_eq!(client.list_users().await.unwrap()[0]["username"], "a");
        assert_eq!(server.take()[0].parsed().header("authorization"), Some("Bearer internal-token"));
    }

    #[tokio::test]
    async fn telemt_adapter_does_not_leak_secret_in_errors() {
        let secret = "ee00112233445566778899aabbccddeeff";
        let (_server, client) = telemt_server(move |_| Reply::Answer(500, secret.as_bytes().to_vec()));
        let error = client.create_user("alice", None).await.unwrap_err();
        assert!(!error.to_string().contains(secret));
        assert_eq!(error.message, "Telemt API error (500)");
    }
}

/// A small stateful version-agent: versions, an update guarded by `expected_current`, the
/// manager rebuild and the meter sample.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn version_agent_fake_round_trip() {
    let server = FakeServer::unix();
    let current = Arc::new(Mutex::new("2.11.6".to_string()));
    let state = current.clone();
    server.respond(move |request| {
        let path = request.line.split(' ').nth(1).unwrap().to_string();
        let mut current = state.lock().unwrap();
        match path.as_str() {
            "/v1/versions" | "/v1/upstream/check" => {
                Reply::json(200, json!({"components": [{"name": "naive", "current": *current}]}))
            }
            "/v1/host" => Reply::json(200, json!({"hostname": "node"})),
            "/v1/metrics" => Reply::Answer(503, Vec::new()),
            "/v1/panel/managers/rebuild" => Reply::json(202, json!({"started": true})),
            "/v1/update" => {
                let body = request.json();
                if body["expected_current"] != json!(*current) {
                    return Reply::json(409, json!({"detail": "stale"}));
                }
                *current = body["version"].as_str().unwrap().to_string();
                Reply::json(200, json!({"component": body["component"], "current": *current}))
            }
            _ => Reply::json(404, json!({"detail": "not found"})),
        }
    });
    let agent = VersionClient::new(server.socket());
    assert_eq!(agent.list_versions().await.unwrap()["components"][0]["current"], "2.11.6");
    assert_eq!(agent.host().await.unwrap()["hostname"], "node");
    assert_eq!(agent.metrics().await, None);
    assert_eq!(agent.rebuild_managers().await.unwrap()["started"], true);
    let stale = agent.update("naive", "2.11.7", Some("2.11.5")).await.unwrap_err();
    assert_eq!((stale.status_code, stale.message.as_str()), (409, "version agent rejected request"));
    assert_eq!(agent.update("naive", "2.11.7", Some("2.11.6")).await.unwrap()["current"], "2.11.7");
    assert_eq!(agent.check().await.unwrap()["components"][0]["current"], "2.11.7");
    let requests: Vec<_> = server.take().iter().map(|r| r.parsed()).collect();
    assert!(requests.iter().all(|r| r.headers.iter().all(|(name, _)| !name.ends_with("-token"))));
    let update = requests.iter().find(|r| r.line.starts_with("POST /v1/update")).unwrap();
    assert_eq!(update.body, br#"{"component":"naive","version":"2.11.7","expected_current":"2.11.5"}"#);
    let missing = VersionClient::new(server.socket().with_file_name("none.sock")).list_versions().await.unwrap_err();
    assert_eq!((missing.status_code, missing.message.as_str()), (502, "version agent unavailable"));
}

/// The journal file against the bytes the Python adapter wrote (`fixtures/telemt-journal.json`,
/// made by `fixtures/record_journal.py`).
mod telemt_journal {
    use super::*;
    use base64::Engine as _;
    use std::os::unix::fs::PermissionsExt;

    fn golden() -> Value {
        serde_json::from_str(include_str!("fixtures/telemt-journal.json")).unwrap()
    }

    #[test]
    fn journal_is_written_byte_identical_to_python() {
        let golden = golden();
        let dir = TempDir::new("wp5-journal");
        let path = dir.path().join("telemt-egress.json");
        let journal = TelemtEgressJournal::new(Some(path.clone()));
        assert_eq!(journal.read().unwrap(), golden["read_missing"]["value"]);
        journal.write(&golden["journal"]).unwrap();
        let written = std::fs::read(&path).unwrap();
        let expected =
            base64::engine::general_purpose::STANDARD.decode(golden["written_b64"].as_str().unwrap()).unwrap();
        assert_eq!(written, expected);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(u64::from(mode), golden["mode"].as_u64().unwrap());
        let files: Vec<String> =
            std::fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        assert_eq!(json!(files), golden["files_after_write"]);
        assert_eq!(journal.read().unwrap(), golden["read_back"]["value"]);
        // The Python-written file reads back the same way.
        std::fs::write(&path, &expected).unwrap();
        assert_eq!(journal.read().unwrap(), golden["journal"]);
    }

    #[test]
    fn unreadable_journal_needs_a_human() {
        let golden = golden();
        let dir = TempDir::new("wp5-journal");
        let path = dir.path().join("telemt-egress.json");
        let journal = TelemtEgressJournal::new(Some(path.clone()));
        std::fs::write(&path, "{not json").unwrap();
        let error = journal.read().unwrap_err();
        assert_eq!(error.to_string(), golden["read_corrupt"]["message"]);
        assert_eq!(panel_managers::JournalUnreadable::CODE, golden["read_corrupt"]["code"]);
        // Python hands `[1]` back and its caller then fails on `.get`; Rust refuses it here.
        std::fs::write(&path, "[1]").unwrap();
        assert_eq!(golden["read_list"]["value"], json!([1]));
        assert!(journal.read().is_err());
    }

    #[test]
    fn journal_without_a_path_lives_in_memory() {
        let journal = TelemtEgressJournal::new(None);
        assert_eq!(journal.read().unwrap(), json!({"current": null, "previous": null, "direct_upstreams": null}));
        journal.write(&json!({"current": {"x": 1}, "previous": null, "direct_upstreams": null})).unwrap();
        assert_eq!(journal.read().unwrap()["current"]["x"], 1);
    }
}
