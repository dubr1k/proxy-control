//! Ported from `tests/test_version_agent_server.py`, the socket cases of
//! `test_version_agent_host.py` / `test_version_agent_hostmetrics.py` and `test_http_endpoints`
//! of `test_version_agent_managers.py`: the real server on a temporary socket, fake agents.

use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Mutex;

use serde_json::{json, Value};

use super::*;
use crate::errors::{CatalogError, UpdateError};
use crate::testutil::TempDir;

/// `FakeAgent` of the Python tests.
#[derive(Default)]
struct FakeAgent {
    calls: Mutex<Vec<(String, String, Option<String>)>>,
    failure: Option<AgentError>,
    checked: Mutex<usize>,
    check_failure: Option<AgentError>,
    acked: Mutex<Vec<Value>>,
    update_gate: Option<Arc<UpdateGate>>,
}

struct UpdateGate {
    entered: (Mutex<bool>, std::sync::Condvar),
    release: (Mutex<bool>, std::sync::Condvar),
    finished: Mutex<bool>,
}

impl UpdateGate {
    fn new() -> Self {
        UpdateGate {
            entered: (Mutex::new(false), std::sync::Condvar::new()),
            release: (Mutex::new(false), std::sync::Condvar::new()),
            finished: Mutex::new(false),
        }
    }

    fn enter(&self) {
        *self.entered.0.lock().unwrap() = true;
        self.entered.1.notify_all();
        let mut release = self.release.0.lock().unwrap();
        while !*release {
            release = self.release.1.wait(release).unwrap();
        }
        *self.finished.lock().unwrap() = true;
    }

    fn wait_entered(&self) {
        let mut entered = self.entered.0.lock().unwrap();
        while !*entered {
            entered = self.entered.1.wait(entered).unwrap();
        }
    }

    fn release(&self) {
        *self.release.0.lock().unwrap() = true;
        self.release.1.notify_all();
    }
}

impl Api for FakeAgent {
    fn list_versions(&self) -> Result<Value, AgentError> {
        Ok(json!({"enabled": true, "components": {"telemt": {"current": "old", "available": []}}}))
    }

    fn update(&self, component: &str, version: &str, expected: Option<&str>) -> Result<Value, AgentError> {
        self.calls.lock().unwrap().push((component.into(), version.into(), expected.map(String::from)));
        if let Some(gate) = &self.update_gate {
            gate.enter();
        }
        if let Some(failure) = &self.failure {
            return Err(failure.clone());
        }
        if component == "panel" {
            return Ok(json!({"component": component, "version": version, "changed": true, "async": true}));
        }
        Ok(json!({"component": component, "version": version, "changed": true}))
    }

    fn check_upstream(&self) -> Result<Value, AgentError> {
        *self.checked.lock().unwrap() += 1;
        match &self.check_failure {
            Some(failure) => Err(failure.clone()),
            None => Ok(json!({"enabled": true, "components": {}, "checked_at": 1})),
        }
    }

    fn rebuild_managers(&self) -> Result<Value, AgentError> {
        Err(AgentError::conflict("panel update or manager rebuild is already running"))
    }

    fn ack_managers(&self, names: &Value) -> Result<Value, AgentError> {
        self.acked.lock().unwrap().push(names.clone());
        if names.as_array().is_none_or(|n| n.is_empty()) {
            return Err(AgentError::Invalid("names must be a non-empty list of known managers".into()));
        }
        Ok(json!({"pending_rebuild": [], "rebuilding": false}))
    }
}

/// A running server on a temporary socket; stopped on drop.
struct Running {
    socket: PathBuf,
    handle: pc_common::ShutdownHandle,
    thread: Option<std::thread::JoinHandle<()>>,
    _dir: TempDir,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.handle.shutdown();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn routes(api: Option<Arc<dyn Api>>) -> Routes {
    Routes {
        api,
        host: Arc::new(|| json!({"cpu": null, "memory": null, "swap": null, "disk": null})),
        metrics: None,
        activity: Arc::new(RequestActivity::default()),
    }
}

fn start(routes: Routes) -> Running {
    let dir = TempDir::new("server");
    let socket = dir.join("run/version-agent.sock");
    // SAFETY: getgid has no preconditions.
    let gid = unsafe { libc::getgid() };
    let server = UdsServer::bind(server_options(&socket, None, gid)).unwrap();
    let handle = server.shutdown_handle();
    let thread = std::thread::spawn(move || serve(server, routes));
    Running { socket, handle, thread: Some(thread), _dir: dir }
}

struct Answer {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// Sends raw request bytes and reads the answer to the end.
fn raw(socket: &Path, request: &[u8]) -> Answer {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    stream.write_all(request).unwrap();
    let mut data = Vec::new();
    stream.read_to_end(&mut data).unwrap();
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut parsed = httparse::Response::new(&mut headers);
    let httparse::Status::Complete(length) = parsed.parse(&data).unwrap() else { panic!("partial answer") };
    Answer {
        status: parsed.code.unwrap(),
        headers: parsed
            .headers
            .iter()
            .map(|h| (h.name.to_string(), String::from_utf8_lossy(h.value).into_owned()))
            .collect(),
        body: data[length..].to_vec(),
    }
}

fn get(socket: &Path, path: &str) -> Answer {
    raw(socket, format!("GET {path} HTTP/1.1\r\nHost: version-agent\r\n\r\n").as_bytes())
}

fn post(socket: &Path, path: &str, body: &[u8]) -> Answer {
    let mut request =
        format!("POST {path} HTTP/1.1\r\nHost: version-agent\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    request.extend_from_slice(body);
    raw(socket, &request)
}

#[test]
fn unix_socket_server_preserves_update_contract() {
    let agent = Arc::new(FakeAgent::default());
    let running = start(routes(Some(agent.clone())));
    let listed = get(&running.socket, "/v1/versions");
    assert_eq!(listed.status, 200);
    assert_eq!(listed.json()["components"]["telemt"]["current"], "old");
    // A different key order: the handler must not rely on insertion order.
    let answer =
        post(&running.socket, "/v1/update", br#"{"expected_current": "old", "version": "new", "component": "telemt"}"#);
    assert_eq!(answer.status, 200);
    assert_eq!(*agent.calls.lock().unwrap(), [("telemt".to_string(), "new".to_string(), Some("old".to_string()))]);
    // The Python bytes: compact, sorted, ASCII, no-store.
    assert_eq!(answer.body, br#"{"changed":true,"component":"telemt","version":"new"}"#);
    assert_eq!(answer.header("content-type"), Some("application/json"));
    assert_eq!(answer.header("cache-control"), Some("no-store"));
    // The socket: mode 0660, the configured group.
    let metadata = std::fs::metadata(&running.socket).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o660);
    // SAFETY: getgid has no preconditions.
    assert_eq!(metadata.gid(), unsafe { libc::getgid() });
}

#[test]
fn unix_socket_server_answers_a_panel_update_as_accepted_and_async() {
    let agent = Arc::new(FakeAgent::default());
    let running = start(routes(Some(agent.clone())));
    let answer = post(
        &running.socket,
        "/v1/update",
        &serde_json::to_vec(
            &json!({"component": "panel", "version": "0.11.0-beta.1", "expected_current": "0.10.0-beta.1"}),
        )
        .unwrap(),
    );
    assert_eq!(answer.status, 200);
    assert_eq!(
        answer.json(),
        json!({"component": "panel", "version": "0.11.0-beta.1", "changed": true, "async": true})
    );
    assert_eq!(
        *agent.calls.lock().unwrap(),
        [("panel".to_string(), "0.11.0-beta.1".to_string(), Some("0.10.0-beta.1".to_string()))]
    );
}

fn shutdown_drains_an_accepted_update(component: &str) {
    let gate = Arc::new(UpdateGate::new());
    let agent = Arc::new(FakeAgent { update_gate: Some(gate.clone()), ..FakeAgent::default() });
    let routes = routes(Some(agent));
    let activity = routes.activity.clone();
    let running = start(routes);
    let socket = running.socket.clone();
    let component = component.to_string();
    let request = std::thread::spawn(move || {
        let body =
            serde_json::to_vec(&json!({"component": component, "version": "new", "expected_current": "old"})).unwrap();
        post(&socket, "/v1/update", &body)
    });
    gate.wait_entered();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let draining = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        activity.stop_and_wait();
        done_tx.send(()).unwrap();
    });
    started_rx.recv().unwrap();
    assert!(done_rx.recv_timeout(Duration::from_millis(50)).is_err());
    gate.release();
    assert_eq!(request.join().unwrap().status, 200);
    done_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    draining.join().unwrap();
    assert!(*gate.finished.lock().unwrap());
    assert_eq!(get(&running.socket, "/v1/health").status, 503);
}

#[test]
fn shutdown_drains_a_component_update_before_exit() {
    shutdown_drains_an_accepted_update("mita");
}

#[test]
fn shutdown_drains_panel_worker_registration_before_exit() {
    shutdown_drains_an_accepted_update("panel");
}

#[test]
fn unix_socket_server_checks_upstream_on_post() {
    let agent = Arc::new(FakeAgent::default());
    let running = start(routes(Some(agent.clone())));
    let answer = raw(&running.socket, b"POST /v1/upstream/check HTTP/1.1\r\nHost: v\r\n\r\n");
    assert_eq!(answer.status, 200);
    assert_eq!((answer.json()["checked_at"].clone(), *agent.checked.lock().unwrap()), (json!(1), 1));
    // A body is tolerated but never read as input: the check takes no parameters.
    assert_eq!(post(&running.socket, "/v1/upstream/check", b"{}").status, 200);
    assert_eq!(*agent.checked.lock().unwrap(), 2);
    assert_eq!(get(&running.socket, "/v1/upstream/check").status, 404);
    // An unreadable length counts as none; a negative or oversized one is refused.
    let bad = raw(&running.socket, b"POST /v1/upstream/check HTTP/1.1\r\nContent-Length: nope\r\n\r\n");
    assert_eq!(bad.status, 200);
    let negative = raw(&running.socket, b"POST /v1/upstream/check HTTP/1.1\r\nContent-Length: -1\r\n\r\n");
    assert_eq!((negative.status, negative.json()), (413, json!({"detail": "request body too large"})));
    let big = raw(
        &running.socket,
        format!("POST /v1/upstream/check HTTP/1.1\r\nContent-Length: {}\r\n\r\n", MAX_BODY + 1).as_bytes(),
    );
    assert_eq!(big.status, 413);
}

#[test]
fn unix_socket_server_reports_a_failed_or_disabled_upstream_check() {
    let agent = Arc::new(FakeAgent {
        check_failure: Some(AgentError::update("upstream check is disabled on this host")),
        ..FakeAgent::default()
    });
    let running = start(routes(Some(agent)));
    let answer = raw(&running.socket, b"POST /v1/upstream/check HTTP/1.1\r\n\r\n");
    assert_eq!(answer.status, 502);
    assert_eq!(answer.json(), json!({"detail": "upstream check is disabled on this host", "state": "update_failed"}));
    let catalog = Arc::new(FakeAgent {
        check_failure: Some(AgentError::Catalog(CatalogError::new("version catalog unavailable"))),
        ..FakeAgent::default()
    });
    let running = start(routes(Some(catalog)));
    let answer = raw(&running.socket, b"POST /v1/upstream/check HTTP/1.1\r\n\r\n");
    assert_eq!(
        (answer.status, answer.json()),
        (502, json!({"detail": "version catalog unavailable", "state": "update_failed"}))
    );
}

#[test]
fn unix_socket_server_returns_distinct_rollback_failed_state() {
    let body = br#"{"component": "telemt", "version": "new", "expected_current": "old"}"#;
    let cases = [
        (
            AgentError::Update(UpdateError::rollback_failed("restored generation is unhealthy")),
            502,
            json!({"detail": "update failed and the previous generation could not be verified", "state": "rollback_failed"}),
        ),
        (
            AgentError::Update(UpdateError::rolled_back("x")),
            502,
            json!({"detail": "update failed and the previous generation was restored", "state": "rolled_back"}),
        ),
        (AgentError::update("x"), 502, json!({"detail": "update failed", "state": "update_failed"})),
        (
            AgentError::conflict("runtime version changed; reload the versions page"),
            409,
            json!({"detail": "runtime version changed; reload the versions page"}),
        ),
        (
            AgentError::Catalog(CatalogError::new("version is not approved for telemt")),
            422,
            json!({"detail": "version is not approved for telemt"}),
        ),
    ];
    for (failure, status, expected) in cases {
        let running = start(routes(Some(Arc::new(FakeAgent { failure: Some(failure), ..FakeAgent::default() }))));
        let answer = post(&running.socket, "/v1/update", body);
        assert_eq!((answer.status, answer.json()), (status, expected));
    }
}

#[test]
fn update_requests_are_validated_like_python() {
    let agent = Arc::new(FakeAgent::default());
    let running = start(routes(Some(agent.clone())));
    let socket = &running.socket;
    let too_large = json!({"detail": "request body too large"});
    // No Content-Length is 413 for an update (Python's default of -1).
    let missing = raw(socket, b"POST /v1/update HTTP/1.1\r\nHost: v\r\n\r\n");
    assert_eq!((missing.status, missing.json()), (413, too_large.clone()));
    let bad = raw(socket, b"POST /v1/update HTTP/1.1\r\nContent-Length: x\r\n\r\n");
    assert_eq!(bad.status, 413);
    let big = raw(socket, format!("POST /v1/update HTTP/1.1\r\nContent-Length: {}\r\n\r\n", MAX_BODY + 1).as_bytes());
    assert_eq!((big.status, big.json()), (413, too_large));
    for body in [&b"not json"[..], b"", b"\xff"] {
        let answer = post(socket, "/v1/update", body);
        assert_eq!((answer.status, answer.json()), (422, json!({"detail": "invalid JSON"})), "{body:?}");
    }
    for body in [
        json!([]),
        json!({"component": "telemt", "version": "1"}),
        json!({"component": "telemt", "version": "1", "expected_current": null, "extra": 1}),
        json!({"component": 5, "version": "1", "expected_current": null}),
        json!({"component": "telemt", "version": true, "expected_current": null}),
        json!({"component": "telemt", "version": "1", "expected_current": 3}),
    ] {
        let answer = post(socket, "/v1/update", body.to_string().as_bytes());
        assert_eq!((answer.status, answer.json()), (422, json!({"detail": "invalid update request"})), "{body}");
    }
    let ok = post(socket, "/v1/update", br#"{"component": "telemt", "version": "1", "expected_current": null}"#);
    assert_eq!(ok.status, 200);
    assert_eq!(agent.calls.lock().unwrap().last().unwrap(), &("telemt".to_string(), "1".to_string(), None));
}

#[test]
fn routing_is_by_exact_path() {
    let running = start(routes(Some(Arc::new(FakeAgent::default()))));
    let socket = &running.socket;
    let health = get(socket, "/v1/health");
    assert_eq!(health.status, 200);
    let identity = health.json();
    assert_eq!(identity["status"], "ok");
    assert_eq!(identity["implementation"], "rust");
    assert_eq!(identity["version"], include_str!("../../../VERSION").trim());
    for path in ["/v1/health?x=1", "/v1/health/", "/v1/nope", "http://version-agent/v1/health"] {
        let answer = get(socket, path);
        assert_eq!((answer.status, answer.json()), (404, json!({"detail": "not found"})), "{path}");
    }
    assert_eq!(post(socket, "/v1/versions", b"{}").status, 404);
    assert_eq!(post(socket, "/v1/update?x=1", b"{}").status, 404);
    assert_eq!(raw(socket, b"PUT /v1/update HTTP/1.1\r\nContent-Length: 0\r\n\r\n").status, 501);
    assert_eq!(raw(socket, b"DELETE /v1/health HTTP/1.1\r\n\r\n").status, 501);
}

#[test]
fn the_listing_failure_is_the_catalog_message() {
    struct Broken;
    impl Api for Broken {
        fn list_versions(&self) -> Result<Value, AgentError> {
            Err(AgentError::update("version state is unreadable"))
        }
        fn update(&self, _: &str, _: &str, _: Option<&str>) -> Result<Value, AgentError> {
            unreachable!()
        }
        fn check_upstream(&self) -> Result<Value, AgentError> {
            unreachable!()
        }
        fn rebuild_managers(&self) -> Result<Value, AgentError> {
            Ok(json!({}))
        }
        fn ack_managers(&self, _: &Value) -> Result<Value, AgentError> {
            Err(AgentError::Internal("state could not be saved".into()))
        }
    }
    let running = start(routes(Some(Arc::new(Broken))));
    let answer = get(&running.socket, "/v1/versions");
    assert_eq!((answer.status, answer.json()), (503, json!({"detail": "version catalog unavailable"})));
    let answer = post(&running.socket, "/v1/panel/managers/ack", br#"{"names": ["docker"]}"#);
    assert_eq!((answer.status, answer.json()), (500, json!({"detail": "state could not be saved"})));
}

#[test]
fn http_endpoints() {
    let agent = Arc::new(FakeAgent::default());
    let running = start(routes(Some(agent.clone())));
    let socket = &running.socket;
    let ack = |body: Value| post(socket, "/v1/panel/managers/ack", body.to_string().as_bytes());
    assert_eq!(ack(json!({"names": []})).status, 422);
    assert_eq!(ack(json!({"other": 1})).json(), json!({"detail": "invalid acknowledge request"}));
    assert_eq!(ack(json!({"names": ["x"], "other": 1})).status, 422);
    let answer = ack(json!({"names": ["naive_manager"]}));
    assert_eq!((answer.status, answer.json()["pending_rebuild"].clone()), (200, json!([])));
    // An empty body is `null`: not an object.
    let empty = raw(socket, b"POST /v1/panel/managers/ack HTTP/1.1\r\n\r\n");
    assert_eq!((empty.status, empty.json()), (422, json!({"detail": "invalid acknowledge request"})));
    let broken = post(socket, "/v1/panel/managers/ack", b"{");
    assert_eq!((broken.status, broken.json()), (422, json!({"detail": "invalid JSON"})));
    let bad_length = raw(socket, b"POST /v1/panel/managers/ack HTTP/1.1\r\nContent-Length: x\r\n\r\n");
    assert_eq!(bad_length.status, 413);
    let rebuild = post(socket, "/v1/panel/managers/rebuild", b"{}");
    assert_eq!(
        (rebuild.status, rebuild.json()),
        (409, json!({"detail": "panel update or manager rebuild is already running"}))
    );
}

#[test]
fn host_endpoint_is_read_only_and_rejects_writes() {
    let running = start(Routes {
        api: None,
        host: Arc::new(|| crate::host::HostReader::default().host_metrics()),
        metrics: None,
        activity: Arc::new(RequestActivity::default()),
    });
    let answer = get(&running.socket, "/v1/host");
    assert_eq!(answer.status, 200);
    let keys: Vec<String> = answer.json().as_object().unwrap().keys().cloned().collect();
    assert_eq!(keys, ["cpu", "disk", "memory", "swap"]);
    // The endpoint takes no input, so POST stays a 404, not a route.
    assert_eq!(post(&running.socket, "/v1/host", b"{}").status, 404);
}

#[test]
fn route_over_the_agent_socket_warming_then_sample() {
    use crate::hostmetrics::tests::{make, FakeHost, Options, TestClock};
    let (host, clock) = (FakeHost::new(), TestClock::new());
    let sampler = Arc::new(make(&host, &clock, Options::default()));
    let running = start(Routes { metrics: Some(sampler.clone()), ..routes(None) });
    let cold = get(&running.socket, "/v1/metrics");
    assert_eq!((cold.status, cold.json()), (503, json!({"detail": "metrics_warming_up"})));
    sampler.tick();
    clock.advance(1.0);
    sampler.tick();
    let warm = get(&running.socket, "/v1/metrics");
    assert_eq!((warm.status, warm.header("cache-control")), (200, Some("no-store")));
    assert_eq!(warm.json()["host"]["cores"], json!(4));
}

// --- the automatic upstream check -----------------------------------------------------------

struct Counting {
    last: Option<i64>,
    failures: Mutex<usize>,
    checks: Mutex<usize>,
}

impl Checked for Counting {
    fn upstream_checked_at(&self) -> Option<i64> {
        self.last
    }

    fn check_upstream(&self) -> Result<Value, AgentError> {
        *self.checks.lock().unwrap() += 1;
        let mut failures = self.failures.lock().unwrap();
        if *failures > 0 {
            *failures -= 1;
            return Err(AgentError::update("api.github.com did not answer"));
        }
        Ok(json!({}))
    }
}

fn counting(last: Option<i64>, failures: usize) -> Counting {
    Counting { last, failures: Mutex::new(failures), checks: Mutex::new(0) }
}

#[test]
fn the_automatic_upstream_check_waits_for_the_cache_to_age() {
    let interval = 6 * 3600;
    assert_eq!(upstream_due_in(&counting(None, 0), interval, 1_000_000.0), AUTO_CHECK_MIN_DELAY);
    assert_eq!(
        upstream_due_in(&counting(Some(1_000_000 - interval - 5), 0), interval, 1_000_000.0),
        AUTO_CHECK_MIN_DELAY
    );
    assert_eq!(upstream_due_in(&counting(Some(1_000_000 - 3600), 0), interval, 1_000_000.0), (interval - 3600) as f64);
}

#[test]
fn the_automatic_upstream_check_survives_a_failure_and_stops_on_request() {
    let agent = counting(None, 1);
    let waits = Mutex::new(Vec::new());
    let wait = |seconds: f64| {
        let mut waits = waits.lock().unwrap();
        waits.push(seconds);
        waits.len() == 4
    };
    auto_check_upstream(&agent, 3600, &wait, &|| 0.0);
    // first delay → failed check → retry pause → next delay → successful check → stop
    assert_eq!(*agent.checks.lock().unwrap(), 2);
    assert_eq!(*waits.lock().unwrap(), [60.0, AUTO_CHECK_RETRY, 60.0, 60.0]);
}

#[test]
fn stop_signal_wakes_a_waiting_thread() {
    let stop = Arc::new(StopSignal::default());
    let waiter = stop.clone();
    let thread = std::thread::spawn(move || waiter.wait(60.0));
    std::thread::sleep(Duration::from_millis(50));
    stop.stop();
    assert!(thread.join().unwrap());
    assert!(stop.wait(5.0));
}
