use super::*;
use crate::testkit::TempDir;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
type RecordedRequest = (String, String, Vec<u8>, BTreeMap<String, String>);
struct Fixture {
    responses: RefCell<VecDeque<ApiResponse>>,
    calls: RefCell<Vec<RecordedRequest>>,
}
impl Fixture {
    fn new(responses: Vec<ApiResponse>) -> Self {
        Self { responses: RefCell::new(responses.into()), calls: RefCell::new(vec![]) }
    }
}
impl Transport for &Fixture {
    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
        headers: &BTreeMap<String, String>,
    ) -> Result<ApiResponse, Error> {
        self.calls.borrow_mut().push((method.into(), path.into(), body.unwrap_or_default().to_vec(), headers.clone()));
        self.responses.borrow_mut().pop_front().ok_or_else(|| failure("fixture exhausted"))
    }
}
fn page() -> ApiResponse {
    ApiResponse {
        status: 200,
        body: b"<meta name='csrf-token' content='abcdefghijklmnop'>".to_vec(),
        cookies: vec!["pre=before; Path=/".into()],
    }
}
fn response(document: Value) -> ApiResponse {
    ApiResponse { status: 200, body: serde_json::to_vec(&document).unwrap(), cookies: vec![] }
}
fn login_response() -> ApiResponse {
    ApiResponse {
        status: 200,
        body: b"{\"success\":true}".to_vec(),
        cookies: vec!["other=one; Path=/".into(), "X-Session=authenticated; HttpOnly".into()],
    }
}
#[test]
fn csrf_meta_and_cookie_are_sent_before_login() {
    let fixture = Fixture::new(vec![page(), login_response()]);
    let mut api = ThreeXuiApi::new(&fixture, "/private/").unwrap();
    api.login("owner", "s e+c&r").unwrap();
    let calls = fixture.calls.borrow();
    assert_eq!(calls[0].1, "/private/");
    assert_eq!(calls[1].1, "/private/login");
    assert_eq!(calls[1].3["Cookie"], "pre=before");
    assert_eq!(calls[1].3["X-CSRF-Token"], "abcdefghijklmnop");
    assert!(String::from_utf8_lossy(&calls[1].2).contains("password=s+e%2Bc%26r"));
    assert_eq!(api.cookie.as_deref(), Some("X-Session=authenticated"));
}
#[test]
fn csrf_missing_fails_before_credentials_are_sent() {
    let mut bad = page();
    bad.body = b"<html>missing</html>".to_vec();
    let fixture = Fixture::new(vec![bad]);
    let mut api = ThreeXuiApi::new(&fixture, "/").unwrap();
    assert!(api.login("owner", "SECRET").is_err());
    assert_eq!(fixture.calls.borrow().len(), 1);
}
#[test]
fn csrf_token_validation() {
    for page in ["", "<meta name='csrf-token' content='short'>", "<meta name='csrf-token' content='abcdefghijklmnop!'>"]
    {
        assert!(parse_csrf_token(page).is_err());
    }
    assert_eq!(parse_csrf_token("<META name=\"CSRF-TOKEN\" content='abcdefghijklmnop'>").unwrap(), "abcdefghijklmnop");
}
#[test]
fn missing_session_cookie_is_rejected() {
    let fixture = Fixture::new(vec![page(), response(json!({"success":true}))]);
    let mut api = ThreeXuiApi::new(&fixture, "/").unwrap();
    assert!(api.login("owner", "SECRET").unwrap_err().to_string().contains("no session cookie"));
}
#[test]
fn rotation_drops_session() {
    let fixture = Fixture::new(vec![page(), login_response(), response(json!({"success":true}))]);
    let mut api = ThreeXuiApi::new(&fixture, "/").unwrap();
    api.login("owner", "secret").unwrap();
    api.rotate_credentials("owner", "secret", "next", "new-secret").unwrap();
    assert!(api.cookie.is_none());
    assert!(api.csrf.is_none());
    assert!(api.settings().is_err());
    assert_eq!(fixture.calls.borrow().len(), 3);
}
#[test]
fn whole_settings_form_preserves_python_str_urlencode() {
    let settings = json!({"webPort":2053,"hasPassword":true,"keepBool":true,"null":null,"list":[true,null,"a'b"],"nested":{"key":false},"unicode":"Привет"});
    let fixture = Fixture::new(vec![
        page(),
        login_response(),
        response(json!({"success":true,"obj":settings})),
        response(json!({"success":true})),
    ]);
    let mut api = ThreeXuiApi::new(&fixture, "/").unwrap();
    api.login("owner", "secret").unwrap();
    api.configure_panel("/private/", 8451, "127.0.0.1", Some("/cert.pem"), Some("/key.pem")).unwrap();
    let body = String::from_utf8(fixture.calls.borrow()[3].2.clone()).unwrap();
    assert!(body.contains("keepBool=true"));
    assert!(body.contains("null=None"));
    assert!(body.contains("list=%5BTrue%2C+None%2C+%22a%27b%22%5D"));
    assert!(body.contains("nested=%7B%27key%27%3A+False%7D"));
    assert!(!body.contains("hasPassword"));
    assert!(body.contains("webPort=8451"));
    assert!(body.contains("webCertFile=%2Fcert.pem"));
}
#[test]
fn form_encoding_matches_scalar_contract() {
    for (value, expected) in [
        (Value::Null, "None"),
        (json!(true), "True"),
        (json!(false), "False"),
        (json!(1.5), "1.5"),
        (json!("a +&/"), "a +&/"),
    ] {
        assert_eq!(python_repr(&value, false), expected);
    }
    assert_eq!(quote_plus("a +&/Пр"), "a+%2B%26%2F%D0%9F%D1%80");
}
#[test]
fn panel_security_validation() {
    let fixture = Fixture::new(vec![]);
    let mut api = ThreeXuiApi::new(&fixture, "/").unwrap();
    assert!(api.configure_panel("bad", 8451, "127.0.0.1", None, None).is_err());
    assert!(api.configure_panel("/ok/", 8451, "0.0.0.0", None, None).is_err());
    assert!(api.configure_panel("/ok/", 0, "127.0.0.1", None, None).is_err());
    assert!(api.configure_panel("/ok/", 8451, "127.0.0.1", Some("relative"), None).is_err());
    assert!(fixture.calls.borrow().is_empty());
}
#[test]
fn rejects_unknown_endpoint_and_unsafe_path_parameter() {
    let fixture = Fixture::new(vec![]);
    let mut api = ThreeXuiApi::new(&fixture, "/").unwrap();
    assert!(api.call("not-reviewed", &Map::new(), &BTreeMap::new(), false).is_err());
    assert!(api
        .call("delete_client", &Map::new(), &BTreeMap::from([("email".into(), "../../secret".into())]), false)
        .is_err());
    assert!(api.call("delete_client", &Map::new(), &BTreeMap::new(), false).is_err());
    assert!(fixture.calls.borrow().is_empty());
}
#[test]
fn permanent_clients_cannot_be_deleted() {
    let fixture = Fixture::new(vec![]);
    let mut api = ThreeXuiApi::new(&fixture, "/").unwrap();
    assert!(api.delete_acceptance_client("initial-0", true).is_err());
    assert!(api.delete_acceptance_client("acceptance-0", false).is_err());
    assert!(fixture.calls.borrow().is_empty());
}
#[test]
fn refusal_never_leaks_upstream_message() {
    let fixture = Fixture::new(vec![
        page(),
        login_response(),
        response(json!({"success":false,"msg":"password=SECRET token=BEARER privateKey=PRIVATE"})),
    ]);
    let mut api = ThreeXuiApi::new(&fixture, "/").unwrap();
    api.login("owner", "secret").unwrap();
    let error = api.settings().unwrap_err().to_string();
    assert!(error.contains("rejected"));
    for secret in ["SECRET", "BEARER", "PRIVATE"] {
        assert!(!error.contains(secret));
    }
}
#[test]
fn malformed_and_wrong_shape_responses_fail_closed() {
    for body in [b"not-json".as_slice(), b"[]", b"{}", b"{\"success\":false}", b"{\"success\":1}"] {
        let fixture = Fixture::new(vec![
            page(),
            login_response(),
            ApiResponse { status: 200, body: body.to_vec(), cookies: vec![] },
        ]);
        let mut api = ThreeXuiApi::new(&fixture, "/").unwrap();
        api.login("owner", "secret").unwrap();
        assert!(api.settings().is_err());
    }
}
#[test]
fn response_bound_is_enforced_for_injected_transport() {
    let fixture = Fixture::new(vec![
        page(),
        login_response(),
        ApiResponse { status: 200, body: vec![b'x'; LIMIT + 1], cookies: vec![] },
    ]);
    let mut api = ThreeXuiApi::new(&fixture, "/").unwrap();
    api.login("owner", "secret").unwrap();
    assert!(api.settings().is_err());
}
#[test]
fn inbound_view_drops_credentials() {
    let fixture = Fixture::new(vec![
        page(),
        login_response(),
        response(
            json!({"success":true,"obj":[{"remark":"a","protocol":"vless","port":8449,"settings":"{\"clients\":[{\"email\":\"initial-0\",\"id\":\"SECRET\"}]}"}]}),
        ),
    ]);
    let mut api = ThreeXuiApi::new(&fixture, "/").unwrap();
    api.login("owner", "secret").unwrap();
    let effective = api.effective_config().unwrap();
    assert!(!effective.to_string().contains("SECRET"));
    assert_eq!(effective["client_emails"], json!(["initial-0"]));
    assert_eq!(effective["inbounds"][0]["client_count"], 1);
}
#[test]
fn subscription_settings_are_sent_whole_and_read_back() {
    let desired = json!({"subEnable":true,"subListen":"127.0.0.1","subPort":2096,"subPath":"/sub/","subURI":"https://sub.example.com/sub/","subDomain":"sub.example.com","subCertFile":"/cert","subKeyFile":"/key","subJsonEnable":false,"subEncrypt":false});
    let fixture = Fixture::new(vec![
        page(),
        login_response(),
        response(json!({"success":true,"obj":{"keep":"retained","hasKey":true}})),
        response(json!({"success":true})),
        response(json!({"success":true,"obj":desired})),
    ]);
    let mut api = ThreeXuiApi::new(&fixture, "/").unwrap();
    api.login("owner", "secret").unwrap();
    api.configure_subscription("sub.example.com", "/cert", "/key").unwrap();
    let body = String::from_utf8(fixture.calls.borrow()[3].2.clone()).unwrap();
    assert!(body.contains("keep=retained"));
    assert!(!body.contains("hasKey"));
}
#[test]
fn subscription_readback_mismatch_is_rejected() {
    let fixture = Fixture::new(vec![
        page(),
        login_response(),
        response(json!({"success":true,"obj":{}})),
        response(json!({"success":true})),
        response(json!({"success":true,"obj":{}})),
    ]);
    let mut api = ThreeXuiApi::new(&fixture, "/").unwrap();
    api.login("owner", "secret").unwrap();
    assert!(api.configure_subscription("sub.example.com", "/cert", "/key").is_err());
}
#[test]
fn loopback_and_path_are_enforced_before_socket() {
    for host in ["example.com", "0.0.0.0", "127.0.0.2"] {
        assert!(ThreeXuiClient::new(host, 8451, None).is_err());
    }
    assert!(ThreeXuiClient::new("127.0.0.1", 0, None).is_err());
    let client = ThreeXuiClient::new("127.0.0.1", 1, None).unwrap();
    for path in ["/ok\r\nsecret", "http://foreign/", "/a?query=secret"] {
        assert!(client.request("POST", path, Some(b"secret"), &BTreeMap::new()).is_err());
    }
}

fn tls_fixture(mismatch: bool) -> (ThreeXuiClient, Arc<AtomicUsize>, std::thread::JoinHandle<()>, TempDir) {
    let root = TempDir::new("three-xui-tls");
    let cert = root.path().join("cert.pem");
    let key = root.path().join("key.pem");
    let status = std::process::Command::new("openssl")
        .args(["req", "-x509", "-newkey", "rsa:2048", "-keyout"])
        .arg(&key)
        .args(["-out"])
        .arg(&cert)
        .args(["-nodes", "-subj", "/CN=panel.example.com", "-days", "1"])
        .output()
        .unwrap();
    assert!(status.status.success());
    let leaf = ThreeXuiClient::new("127.0.0.1", 1, Some(&cert)).unwrap().pin.unwrap();
    let der = root.path().join("key.der");
    assert!(std::process::Command::new("openssl")
        .args(["pkcs8", "-topk8", "-nocrypt", "-in"])
        .arg(&key)
        .args(["-outform", "DER", "-out"])
        .arg(&der)
        .output()
        .unwrap()
        .status
        .success());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.into()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(std::fs::read(der).unwrap()).into(),
        )
        .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let observed = count.clone();
    let thread = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let connection = rustls::ServerConnection::new(Arc::new(config)).unwrap();
        let mut stream = rustls::StreamOwned::new(connection, socket);
        let mut buffer = [0; 4096];
        if let Ok(n) = stream.read(&mut buffer) {
            observed.store(n, Ordering::SeqCst);
            if n > 0 {
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
                let _ = stream.flush();
                let _ = stream.sock.shutdown(std::net::Shutdown::Both);
            }
        }
    });
    let mut client = ThreeXuiClient::new("127.0.0.1", port, Some(&cert)).unwrap();
    if mismatch {
        client.pin.as_mut().unwrap()[0] ^= 1;
    }
    (client, count, thread, root)
}
#[test]
fn leaf_pin_mismatch_sends_no_request_bytes() {
    let (client, count, thread, _root) = tls_fixture(true);
    assert!(client.request("POST", "/login", Some(b"password=SECRET"), &BTreeMap::new()).is_err());
    thread.join().unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 0);
}
#[test]
fn leaf_pin_accepts_installed_leaf_before_credentials() {
    let (client, count, thread, _root) = tls_fixture(false);
    let response = client.request("GET", "/", None, &BTreeMap::new());
    thread.join().unwrap();
    assert_eq!(response.unwrap().status, 200);
    assert!(count.load(Ordering::SeqCst) > 0);
}

#[test]
fn whole_form_keeps_nested_python_dict_insertion_order() {
    let raw = br#"{"success":true,"obj":{"keep":{"z":1,"a":[true,null,{"last":2,"first":3}]},"hasKey":true}}"#;
    let fixture = Fixture::new(vec![
        page(),
        login_response(),
        ApiResponse { status: 200, body: raw.to_vec(), cookies: vec![] },
        response(json!({"success":true})),
    ]);
    let mut api = ThreeXuiApi::new(&fixture, "/").unwrap();
    api.login("owner", "secret").unwrap();
    api.configure_panel("/private/", 8451, "127.0.0.1", None, None).unwrap();
    let body = String::from_utf8(fixture.calls.borrow()[3].2.clone()).unwrap();
    assert!(body.contains(&format!("keep={}", quote_plus("{'z': 1, 'a': [True, None, {'last': 2, 'first': 3}]}"))));
}

#[test]
fn float_form_values_match_python_goldens() {
    let cases: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/host-golden/vectors/float-repr.json")).unwrap();
    for case in cases.as_array().unwrap() {
        let text = case["json"].as_str().unwrap();
        if let Ok(value) = serde_json::from_str::<Value>(text) {
            assert_eq!(python_repr(&value, false), case["repr"].as_str().unwrap(), "{text}");
        }
    }
}

#[test]
fn warp_rejects_existing_tag_and_empty_confirmed_domains() {
    let fixture = Fixture::new(vec![
        page(),
        login_response(),
        response(json!({"success":true,"obj":{"xraySetting":{"outbounds":[{"tag":"WARP"}],"routing":{"rules":[]}}}})),
    ]);
    let mut api = ThreeXuiApi::new(&fixture, "/").unwrap();
    api.login("owner", "secret").unwrap();
    assert!(api.configure_warp(40000, &[]).is_err());
    assert!(api.configure_warp(40000, &["example.com".into()]).unwrap_err().to_string().contains("explicit migration"));
    assert_eq!(fixture.calls.borrow().len(), 3);
}

#[test]
fn warp_merges_existing_template_and_preserves_final_policy_last() {
    let final_rule = json!({"outboundTag":"direct","network":"tcp,udp"});
    let current = json!({"xraySetting":{"outbounds":[{"tag":"direct"}],"routing":{"rules":[final_rule,{"outboundTag":"blocked","domain":["geosite:private"]},final_rule]}},"outboundTestUrl":"https://example.com/probe"});
    let candidate = json!({"outbounds":[{"tag":"direct"},{"tag":"WARP","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":40000}]}}],"routing":{"rules":[{"outboundTag":"blocked","domain":["geosite:private"]},{"type":"field","domain":["domain:example.com","geosite:youtube"],"outboundTag":"WARP"},final_rule]}});
    let fixture = Fixture::new(vec![
        page(),
        login_response(),
        response(json!({"success":true,"obj":current})),
        response(json!({"success":true})),
        response(json!({"success":true,"obj":{"xraySetting":candidate}})),
    ]);
    let mut api = ThreeXuiApi::new(&fixture, "/").unwrap();
    api.login("owner", "secret").unwrap();
    api.configure_warp(40000, &["example.com".into(), "geosite:youtube".into()]).unwrap();
    let body = String::from_utf8(fixture.calls.borrow()[3].2.clone()).unwrap();
    assert!(body.contains(&quote_plus("https://example.com/probe")));
    assert!(body.contains(&quote_plus(&pc_host::json::canonical(&candidate))));
}
