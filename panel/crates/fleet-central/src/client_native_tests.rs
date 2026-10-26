#[tokio::test]
async fn pin_mismatch_never_sends_generation_credentials_or_bearer() {
    let server = TlsServer::start(1, Vec::new());
    let client = NodeHttpClient::new(&server.url, "must-not-leak-bearer", "pin", Some(&"0".repeat(64)), true).unwrap();
    let push=PushRequest::validate(&json!({"expected_guid":"edge","generation":{"node_guid":"edge","master_guid":"central","generation":1,"previous_generation":0,"created_at":1,"created_by":"test","resources":[{"ref":"grant:g","protocol":"naive","runtime_username":"alice","desired_state":"enabled","credential_ref":"grant:g:1","credential_origin":"caller"}]},"secrets":{"grant:g:1":"must-not-leak-credential"}})).unwrap();
    let error = client.push(&push).await.unwrap_err();
    assert!(matches!(error, NodeError::Unreachable(_)));
    assert!(!error.to_string().contains("must-not-leak"));
    assert!(server.requests().is_empty());
    server.finish();
}

struct PolicyResolver {
    allow_private: Arc<std::sync::atomic::AtomicBool>,
    names: Arc<Mutex<Vec<String>>>,
    candidates: Vec<SocketAddr>,
}

impl Resolve for PolicyResolver {
    fn resolve(&self, name: Name) -> Resolving {
        self.names.lock().unwrap().push(name.as_str().into());
        let allowed = self.allow_private.load(std::sync::atomic::Ordering::SeqCst);
        let candidates = self.candidates.clone();
        Box::pin(async move {
            let addresses = checked_addresses(candidates, allowed)
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

#[tokio::test]
async fn resolver_is_rechecked_for_each_connection_and_keeps_original_host_and_sni() {
    let server = TlsServer::start(1, vec![Reply::json(200, json!({"guid":"resolved"}))]);
    let allowed = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let names = Arc::new(Mutex::new(Vec::new()));
    let mut client = server.client("scoped-key");
    client.base_url = server.url.replace("127.0.0.1", "node.example");
    client.http = reqwest::Client::builder()
        .no_proxy()
        .http1_only()
        .dns_resolver(PolicyResolver {
            allow_private: allowed.clone(),
            names: names.clone(),
            candidates: vec!["127.0.0.1:0".parse().unwrap()],
        })
        .tls_backend_preconfigured(pinned_tls_config(Some(server.pin.clone())).unwrap())
        .build()
        .unwrap();
    assert_eq!(client.identity().await.unwrap()["guid"], "resolved");
    allowed.store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(matches!(client.identity().await, Err(NodeError::Unreachable(_))));
    assert_eq!(*names.lock().unwrap(), ["node.example", "node.example"]);
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].server_name.as_deref(), Some("node.example"));
    assert!(requests[0].headers.to_ascii_lowercase().contains("host: node.example:"));
    server.finish();
}

struct PendingResolver;
impl Resolve for PendingResolver {
    fn resolve(&self, _: Name) -> Resolving {
        Box::pin(std::future::pending())
    }
}

#[tokio::test]
async fn dns_and_fingerprint_resolution_deadlines_are_bounded_and_typed() {
    let mut client =
        NodeHttpClient::new("https://node.example", "secret-key", "pin", Some(&"0".repeat(64)), false).unwrap();
    client.http = reqwest::Client::builder()
        .no_proxy()
        .dns_resolver(PendingResolver)
        .connect_timeout(Duration::from_millis(10))
        .timeout(Duration::from_secs(1))
        .tls_backend_preconfigured(pinned_tls_config(None).unwrap())
        .build()
        .unwrap();
    assert_eq!(client.identity().await.unwrap_err(), NodeError::Unreachable("ConnectTimeout".into()));
    assert_eq!(
        fingerprint_addresses("node.example", 443, false, Instant::now() - Duration::from_secs(1)).unwrap_err(),
        NodeError::Unreachable("TimeoutError".into())
    );
}

#[test]
fn fingerprint_deadline_bounds_slow_system_resolution_and_discards_late_answer() {
    let (release, pending) = std::sync::mpsc::channel();
    let (finished, done) = std::sync::mpsc::channel();
    let started = Instant::now();
    let result = fingerprint_addresses_with_resolver(
        "node.example", 443, false, started + Duration::from_millis(20),
        move |host, port| {
            assert_eq!((host.as_str(), port), ("node.example", 443));
            pending.recv().unwrap();
            finished.send(()).unwrap();
            Ok(vec!["8.8.8.8:443".parse().unwrap()])
        },
    );
    assert_eq!(result.unwrap_err(), NodeError::Unreachable("TimeoutError".into()));
    assert!(started.elapsed() < Duration::from_secs(1));
    release.send(()).unwrap();
    done.recv_timeout(Duration::from_secs(1)).unwrap();
}

#[tokio::test]
async fn validated_ipv6_connect_failure_falls_back_to_numeric_ipv4() {
    let server = TlsServer::start(1, vec![Reply::json(200, json!({"guid":"fallback"}))]);
    let mut client = server.client("key");
    client.base_url = server.url.replace("127.0.0.1", "node.example");
    client.http = reqwest::Client::builder()
        .no_proxy()
        .http1_only()
        .dns_resolver(PolicyResolver {
            allow_private: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            names: Arc::new(Mutex::new(Vec::new())),
            candidates: vec!["[::1]:0".parse().unwrap(), "127.0.0.1:0".parse().unwrap()],
        })
        .connect_timeout(Duration::from_secs(2))
        .tls_backend_preconfigured(pinned_tls_config(Some(server.pin.clone())).unwrap())
        .build()
        .unwrap();
    assert_eq!(client.identity().await.unwrap()["guid"], "fallback");
    assert_eq!(server.requests().len(), 1);
    server.finish();
}

#[tokio::test]
async fn redirects_do_not_forward_bearer_to_a_second_origin() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut reply = Reply::json(302, json!({}));
    reply.extra_headers = format!("Location: https://127.0.0.1:{}/internal\r\n", listener.local_addr().unwrap().port());
    let server = TlsServer::start(1, vec![reply]);
    assert!(server.client("private-key").identity().await.unwrap().is_empty());
    assert_eq!(listener.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    assert_eq!(server.requests().len(), 1);
    server.finish();
}

#[tokio::test]
async fn client_scope_reuses_one_tls_connection_for_identity_status_and_inventory() {
    let mut first = Reply::json(200, json!({}));
    first.keep_alive = true;
    let mut second = Reply::json(200, json!({}));
    second.keep_alive = true;
    let server = TlsServer::start(1, vec![first, second, Reply::json(200, json!({}))]);
    let client = server.client("pooled-key");
    client.identity().await.unwrap();
    client.status().await.unwrap();
    client.inventory().await.unwrap();
    assert_eq!(
        server.requests().iter().map(|r| r.request_line.clone()).collect::<Vec<_>>(),
        [
            "GET /api/fleet/v2/identity HTTP/1.1",
            "GET /api/fleet/v2/status HTTP/1.1",
            "GET /api/fleet/v2/inventory HTTP/1.1"
        ]
    );
    drop(client);
    server.finish();
}

#[tokio::test]
async fn metrics_deadline_bounds_the_read_and_transport_error_never_exposes_key() {
    let mut ready = Reply::json(200, json!({}));
    ready.keep_alive = true;
    let mut slow = Reply::json(200, json!({"status":"ok"}));
    slow.delay = Duration::from_millis(200);
    let server = TlsServer::start(1, vec![ready, slow]);
    let client = server.client("never-print-this-key");
    client.identity().await.unwrap();
    let error = client.metrics(Duration::from_millis(20)).await.unwrap_err();
    assert_eq!(error, NodeError::Unreachable("ReadTimeout".into()));
    assert!(!error.to_string().contains("never-print-this-key"));
    server.finish();
}

#[tokio::test]
async fn remaining_node_operations_preserve_methods_queries_bodies_and_json_objects() {
    let server = TlsServer::start(12, (0..12).map(|_| Reply::json(200, json!({"marker":"preserved"}))).collect());
    let client = server.client("key");
    assert_eq!(client.status().await.unwrap()["marker"], "preserved");
    client.inventory().await.unwrap();
    client.unlink().await.unwrap();
    client
        .capture(&[CaptureItem { protocol: "naive".into(), runtime_username: "alice".into() }], CapturePurpose::Import)
        .await
        .unwrap();
    client.check_versions().await.unwrap();
    client.exit_test(&json!({"protocol":"socks","password":"synthetic"}).as_object().unwrap().clone()).await.unwrap();
    client.geodata("view", None).await.unwrap();
    client.geodata("codes", None).await.unwrap();
    client.geodata("settings", Some(&json!({"enabled":true}).as_object().unwrap().clone())).await.unwrap();
    client.geodata("download", None).await.unwrap();
    client.metrics_summary("6h", Duration::from_secs(10)).await.unwrap();
    client.metrics(Duration::from_secs(3)).await.unwrap();
    let requests = server.requests();
    server.finish();
    assert_eq!(
        requests.iter().map(|r| r.request_line.as_str()).collect::<Vec<_>>(),
        [
            "GET /api/fleet/v2/status HTTP/1.1",
            "GET /api/fleet/v2/inventory HTTP/1.1",
            "POST /api/fleet/v2/unlink HTTP/1.1",
            "POST /api/fleet/v2/credentials/capture HTTP/1.1",
            "POST /api/fleet/v2/versions/check HTTP/1.1",
            "POST /api/fleet/v2/exits/test HTTP/1.1",
            "GET /api/fleet/v2/geodata HTTP/1.1",
            "GET /api/fleet/v2/geodata/codes HTTP/1.1",
            "PUT /api/fleet/v2/geodata/settings HTTP/1.1",
            "POST /api/fleet/v2/geodata/download HTTP/1.1",
            "GET /api/fleet/v2/metrics/summary?range=6h HTTP/1.1",
            "GET /api/fleet/v2/metrics HTTP/1.1"
        ]
    );
    assert_eq!(serde_json::from_slice::<Value>(&requests[3].body).unwrap()["purpose"], "import");
    assert_eq!(
        serde_json::from_slice::<Value>(&requests[5].body).unwrap(),
        json!({"exit":{"protocol":"socks","password":"synthetic"}})
    );
    assert_eq!(serde_json::from_slice::<Value>(&requests[8].body).unwrap(), json!({"enabled":true}));
}

#[tokio::test]
async fn empty_malformed_and_non_object_success_bodies_are_empty_objects() {
    let server = TlsServer::start(
        4,
        vec![
            Reply::bytes(204, Vec::new()),
            Reply::json(200, json!([])),
            Reply::json(200, Value::Null),
            Reply::bytes(200, b"not json".to_vec()),
        ],
    );
    let client = server.client("key");
    for _ in 0..4 {
        assert!(client.identity().await.unwrap().is_empty());
    }
    server.finish();
}
