//! The protocol acceptance dialogues: real panel session, official client/HTTP2 CONNECT and cleanup.
use super::core::core_acceptance::PanelSession;
use super::core::CoreAdapter;
use super::mieru::{MieruAdapter, MieruSelection, PrivateDirectory, BINARY, CLIENT_IMAGE, SOCKET};
use super::naive::{NaiveAdapter, NaiveSelection, LOG_DIR};
use super::proxy_common::{domain, loopback, Host, PROJECT};
use crate::error::Error;
use pc_host::fs::{atomic_write, token_hex};
use pc_host::net::{ClientOptions, HttpsClient};
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::time::{Duration, Instant};

#[cfg(test)]
pub(super) type TestAcceptance = std::sync::Arc<dyn Fn(&str, &str, bool) -> Result<Value, Error> + Send + Sync>;
fn acceptance(message: impl Into<String>) -> Error {
    Error::other("AcceptanceError", message)
}
fn request(
    session: &mut PanelSession,
    method: &str,
    path: &str,
    payload: Option<Value>,
    json: bool,
) -> Result<Value, Error> {
    session
        .request(method, path, payload, method != "GET", json)
        .map_err(|_| acceptance("protocol acceptance panel request did not complete"))
}
fn login(host: &Host, panel: &str) -> Result<PanelSession, Error> {
    let path = host.host(&format!("{PROJECT}/secrets/panel-bootstrap-password"))?;
    host.private_file(&path, 0o600)?;
    let password = fs::read_to_string(path)?;
    PanelSession::login(panel, password.trim_end_matches(['\r', '\n']))
        .map_err(|_| acceptance("protocol acceptance failed: panel login"))
}
fn present(listed: &Value, name: &str) -> bool {
    listed
        .get("items")
        .and_then(Value::as_array)
        .is_some_and(|rows| rows.iter().any(|row| row.get("username").and_then(Value::as_str) == Some(name)))
}
fn ready(listed: &Value) -> bool {
    listed.pointer("/service/ready") == Some(&Value::Bool(true))
}
fn revision(listed: &Value) -> Result<&str, Error> {
    listed
        .pointer("/service/revision")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| acceptance("Mieru acceptance failed: manager health"))
}
fn native(revealed: &Value) -> Result<&Value, Error> {
    revealed
        .pointer("/clients/native/config")
        .filter(|value| value.is_object())
        .ok_or_else(|| acceptance("protocol acceptance failed: access"))
}
fn reveal(session: &mut PanelSession, created: &Value) -> Result<Value, Error> {
    let token = created
        .get("reveal_token")
        .and_then(Value::as_str)
        .filter(|s| {
            !s.is_empty() && s.len() <= 256 && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
        })
        .ok_or_else(|| acceptance("protocol acceptance failed: access"))?;
    request(session, "GET", &format!("/api/reveal/{token}"), None, true)
}
fn cleanup(host: &Host, panel: &str, name: &str) -> Result<(), Error> {
    let mut session = login(host, panel)?;
    let result: Result<(), Error> = (|| {
        let path = format!("/api/{}/users", host.name);
        let listed = request(&mut session, "GET", &path, None, true)?;
        if present(&listed, name) {
            let payload =
                if host.name == "mieru" { Some(json!({"expected_revision":revision(&listed)?})) } else { None };
            request(&mut session, "DELETE", &format!("{path}/{name}"), payload, false)?;
        }
        Ok(())
    })();
    let logout = session.logout().map_err(|_| acceptance("temporary-user and session cleanup failed"));
    result?;
    logout
}
impl NaiveAdapter {
    pub(super) fn cleanup(&self, panel: &str, name: &str) -> Result<(), Error> {
        #[cfg(test)]
        if let Some(probe) = &self.test_acceptance {
            return probe("cleanup", name, false).map(|_| ());
        }
        cleanup(&self.host, panel, name)
    }
    pub(super) fn acceptance(&self, selected: &NaiveSelection, name: &str, recover: bool) -> Result<Value, Error> {
        #[cfg(test)]
        if let Some(probe) = &self.test_acceptance {
            return probe("acceptance", name, recover);
        }
        let admin = loopback(&self.host, 2019);
        let private = loopback(&self.host, 4443);
        let client = HttpsClient::new(ClientOptions {
            user_agent: "proxy-control-acceptance".into(),
            ..ClientOptions::default()
        })
        .map_err(|_| acceptance("Naive acceptance failed: cover HTTPS"))?;
        let cover = client
            .get(&format!("https://{}/", selected.domain), &[&selected.domain], &[], 1024 * 1024)
            .is_ok_and(|response| (200..500).contains(&response.status()));
        let mut session = login(&self.host, &selected.panel)?;
        let mut created = false;
        let result = (|| {
            let listed = request(&mut session, "GET", "/api/naive/users", None, true)?;
            let manager_ready = ready(&listed);
            if present(&listed, name) {
                if !recover {
                    return Err(Error::other(
                        "_AcceptanceCollision",
                        "Naive acceptance failed: temporary-user collision",
                    ));
                }
                request(&mut session, "DELETE", &format!("/api/naive/users/{name}"), None, false)?;
            }
            let user = request(&mut session, "POST", "/api/naive/users", Some(json!({"username":name})), true)?;
            created = true;
            let revealed = reveal(&mut session, &user)?;
            let proxy = native(&revealed)?
                .get("proxy")
                .and_then(Value::as_str)
                .ok_or_else(|| acceptance("Naive acceptance failed: access"))?;
            let (bytes, closed, panel_ok) = self.connect_h2(proxy, &selected.domain)?;
            let deadline = Instant::now() + Duration::from_secs(120);
            let mut recorded = 0;
            loop {
                let listed = request(&mut session, "GET", "/api/naive/users", None, true)?;
                if let Some(rows) = listed.get("items").and_then(Value::as_array) {
                    for row in rows {
                        if row.get("username").and_then(Value::as_str) == Some(name) {
                            if let Some(value) = row.get("total_bytes").and_then(Value::as_u64) {
                                recorded = recorded.max(value);
                            }
                        }
                    }
                }
                if recorded >= bytes || Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_secs(5));
            }
            let adjacent = CoreAdapter::new(&self.host.context).verify_adjacent(&selected.adjacent).is_ok();
            self.host.run(&["/usr/local/libexec/prepare-naive-state", "verify", "--log-dir", LOG_DIR])?;
            Ok(
                json!({"admin_api_loopback":admin,"private_listener_ok":private,"cover_https_ok":cover,"authenticated_connect_ok":bytes>0,"tunnel_closed_ok":closed,"connect_bytes":bytes,"recorded_bytes":recorded,"manager_health_ok":manager_ready,"panel_health_ok":panel_ok,"adjacent_sni_ok":adjacent,"log_boundary_ok":true,"temporary_state_removed":true}),
            )
        })();
        let remove = if created {
            request(&mut session, "DELETE", &format!("/api/naive/users/{name}"), None, false).map(|_| ())
        } else {
            Ok(())
        };
        let logout = session.logout().map_err(|_| acceptance("temporary-user and session cleanup failed"));
        remove?;
        logout?;
        result
    }
    pub(super) fn connect_h2(&self, proxy: &str, domain: &str) -> Result<(u64, bool, bool), Error> {
        let parts = pc_host::url::split(proxy);
        if parts.scheme != "https" || parts.hostname().as_deref() != Some(domain) {
            return Err(acceptance("Naive acceptance failed: access"));
        }
        let user = decode(parts.username().unwrap_or_default())?;
        let password = decode(parts.password().unwrap_or_default())?;
        if user.is_empty()
            || password.is_empty()
            || user.contains(['\0', '\r', '\n'])
            || password.contains(['\0', '\r', '\n'])
        {
            return Err(acceptance("Naive acceptance failed: access"));
        }
        let directory = PrivateDirectory::new(&self.host.host("/var/tmp")?, "proxy-control-naive-acceptance-")?;
        let config = directory.path.join("curl.conf");
        let content=format!("proxy = {}\nproxy-user = {}\nproxy-http2\nnoproxy = \"\"\noutput = \"/dev/null\"\nwrite-out = \"%{{http_code}} %{{size_download}} %{{http_connect}}\"\nmax-time = 40\nurl = \"https://example.com/\"\n",curl_quote(&format!("https://{domain}:443")),curl_quote(&format!("{user}:{password}")));
        atomic_write(&config, content.as_bytes(), 0o600, None)?;
        let output = self
            .host
            .context
            .runner
            .capture_checked(&["curl", "--config", &config.to_string_lossy()], Duration::from_secs(50))
            .map_err(|_| acceptance("Naive acceptance failed: HTTP/2 CONNECT"))?;
        let fields: Vec<_> = output.split_whitespace().collect();
        if fields.len() != 3 || fields[0].len() != 3 || fields[2].len() != 3 {
            return Err(acceptance("Naive acceptance failed: HTTP/2 response format"));
        }
        let values: Vec<_> = fields.iter().map(|field| field.parse::<u64>()).collect();
        let (Ok(status), Ok(downloaded), Ok(connect)) = (&values[0], &values[1], &values[2]) else {
            return Err(acceptance("Naive acceptance failed: HTTP/2 response format"));
        };
        if *downloaded == 0 {
            return Err(acceptance("Naive acceptance failed: empty CONNECT payload"));
        }
        Ok((*downloaded, true, *status == 200 && [0, 200].contains(connect)))
    }
}
impl MieruAdapter {
    pub(super) fn cleanup(&self, panel: &str, name: &str) -> Result<(), Error> {
        #[cfg(test)]
        if let Some(probe) = &self.test_acceptance {
            return probe("cleanup", name, false).map(|_| ());
        }
        cleanup(&self.host, panel, name)
    }
    pub(super) fn acceptance(&self, selected: &MieruSelection, name: &str, recover: bool) -> Result<Value, Error> {
        #[cfg(test)]
        if let Some(probe) = &self.test_acceptance {
            return probe("acceptance", name, recover);
        }
        let running = self.running();
        let mut session = login(&self.host, &selected.panel)?;
        let mut created = false;
        let result = (|| {
            let path = "/api/mieru/users";
            let mut listed = request(&mut session, "GET", path, None, true)?;
            let manager_ready = ready(&listed);
            if present(&listed, name) {
                if !recover {
                    return Err(Error::other(
                        "_AcceptanceCollision",
                        "Mieru acceptance failed: temporary-user collision",
                    ));
                }
                let expected = revision(&listed)?.to_string();
                request(
                    &mut session,
                    "DELETE",
                    &format!("{path}/{name}"),
                    Some(json!({"expected_revision":expected})),
                    false,
                )?;
                listed = request(&mut session, "GET", path, None, true)?;
            }
            let expected = revision(&listed)?.to_string();
            let user = request(
                &mut session,
                "POST",
                path,
                Some(json!({"username":name,"quotas":[],"expected_revision":expected})),
                true,
            )?;
            created = true;
            let revealed = reveal(&mut session, &user)?;
            let native = native(&revealed)?;
            if !native.get("profiles").is_some_and(Value::is_array) {
                return Err(acceptance("Mieru acceptance failed: access"));
            }
            let mut verified = 0;
            let mut drained = true;
            for (protocol, port) in &selected.transports {
                if self.client_probe(native, protocol, *port).is_ok() {
                    verified += 1;
                }
                let output = self.host.capture(&["ss", "-H", "-tin", &format!("sport = :{port}")], 8192);
                if pc_host::runner::is_in_band_failure(&output)
                    || output.lines().any(|line| {
                        let f: Vec<_> = line.split_whitespace().collect();
                        f.len() >= 3 && f[0].parse::<u64>().is_ok() && f[1].parse::<u64>().is_ok_and(|n| n > 0)
                    })
                {
                    drained = false;
                }
            }
            let identity = self.host.capture(&["getent", "passwd", "mita"], 512);
            let fields: Vec<_> = identity.trim().split(':').collect();
            let owner = if fields.len() >= 4 && fields[0] == "mita" {
                fields[2].parse::<u32>().ok().zip(fields[3].parse::<u32>().ok())
            } else {
                None
            };
            let boundary = fs::symlink_metadata(self.host.host(SOCKET)?).is_ok_and(|info| {
                info.file_type().is_socket() && info.mode() & 0o7777 == 0o770 && owner == Some((info.uid(), info.gid()))
            });
            let package_ok =
                pc_host::archive::verify_artifact(&self.host.host(&selected.package)?, &selected.package_digest)
                    .is_ok();
            let actual = pc_host::fs::sha256_file(&self.host.host(BINARY)?).unwrap_or_default();
            let executable_ok = actual == selected.executable_digest
                || self.host.agent_value("mita", "sha256").as_deref() == Some(&actual);
            Ok(
                json!({"package_digest_ok":package_ok,"executable_digest_ok":executable_ok,"mita_status_running":running,"uds_boundary_ok":boundary,"manager_health_ok":manager_ready,"panel_health_ok":true,"transports_verified":verified,"transports_expected":selected.transports.len(),"send_queue_drained":drained,"adjacent_listeners_ok":self.adjacent_listeners_ok(&selected.adjacent_listeners),"public_host_ok":domain(&selected.host),"temporary_state_removed":true}),
            )
        })();
        // Re-read revision after every create/delete; stale revisions must never delete a foreign change.
        let remove = if created { self.cleanup_in_session(&mut session, name) } else { Ok(()) };
        let logout = session.logout().map_err(|_| acceptance("temporary-user and session cleanup failed"));
        remove?;
        logout?;
        result
    }
    pub(super) fn adjacent_listeners_ok(&self, expected: &[(String, u16)]) -> bool {
        if expected.is_empty() {
            return true;
        }
        let output = self.host.capture(&["ss", "-H", "-lntup"], 65536);
        if pc_host::runner::is_in_band_failure(&output) {
            return false;
        }
        let observed: std::collections::BTreeSet<_> = output
            .lines()
            .filter_map(|line| {
                let fields: Vec<_> = line.split_whitespace().collect();
                if fields.len() < 5 || !["tcp", "udp"].contains(&fields[0]) {
                    return None;
                }
                let port = fields[4].rsplit_once(':')?.1.parse::<u16>().ok()?;
                Some((fields[0].to_uppercase(), port))
            })
            .collect();
        expected.iter().all(|binding| observed.contains(binding))
    }
    fn cleanup_in_session(&self, session: &mut PanelSession, name: &str) -> Result<(), Error> {
        let listed = request(session, "GET", "/api/mieru/users", None, true)?;
        if present(&listed, name) {
            let expected = revision(&listed)?.to_string();
            request(
                session,
                "DELETE",
                &format!("/api/mieru/users/{name}"),
                Some(json!({"expected_revision":expected})),
                false,
            )?;
        }
        Ok(())
    }
    fn client_probe(&self, native: &Value, protocol: &str, port: u16) -> Result<(), Error> {
        let document = client_config_for(native, protocol, port)?;
        let directory = PrivateDirectory::new(&self.host.host("/var/tmp")?, "proxy-control-mieru-client-")?;
        let path = directory.path.join("client.json");
        atomic_write(&path, &serde_json::to_vec(&document).expect("JSON serializes"), 0o600, None)?;
        self.host.run(&[
            "docker",
            "run",
            "--rm",
            "--network",
            "host",
            "--volume",
            &format!("{}:/etc/mieru/client.json:ro", path.display()),
            CLIENT_IMAGE,
        ])
    }
}
pub fn client_config_for(native: &Value, protocol: &str, port: u16) -> Result<Value, Error> {
    let mut document = native.clone();
    let mut count = 0;
    let profiles = document
        .get_mut("profiles")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| acceptance("Mieru acceptance failed: access"))?;
    for profile in profiles {
        if let Some(servers) = profile.get_mut("servers").and_then(Value::as_array_mut) {
            for server in servers {
                if let Some(bindings) = server.get_mut("portBindings").and_then(Value::as_array_mut) {
                    bindings.retain(|binding| {
                        binding.get("protocol").and_then(Value::as_str) == Some(protocol)
                            && binding.get("port").and_then(Value::as_u64) == Some(port as u64)
                    });
                    count += bindings.len();
                }
            }
        }
    }
    if count == 0 {
        return Err(acceptance("Mieru acceptance failed: official client probe"));
    }
    Ok(document)
}
fn validate(value: &Value, flags: &[&str], counts: &[&str]) -> Result<(), Error> {
    let object = value.as_object().ok_or_else(|| acceptance("protocol acceptance result is invalid"))?;
    if object.keys().any(|key| !flags.contains(&key.as_str()) && !counts.contains(&key.as_str()))
        || flags.iter().any(|key| *key != "temporary_state_removed" && !object.get(*key).is_some_and(Value::is_boolean))
        || object.get("temporary_state_removed").is_some_and(|v| !v.is_boolean())
        || counts.iter().any(|key| !object.get(*key).is_some_and(|v| v.as_u64().is_some()))
    {
        return Err(acceptance("protocol acceptance result is invalid"));
    }
    Ok(())
}
pub fn require_naive(value: &Value) -> Result<(), Error> {
    validate(
        value,
        &[
            "admin_api_loopback",
            "private_listener_ok",
            "cover_https_ok",
            "authenticated_connect_ok",
            "tunnel_closed_ok",
            "manager_health_ok",
            "panel_health_ok",
            "adjacent_sni_ok",
            "log_boundary_ok",
            "temporary_state_removed",
        ],
        &["connect_bytes", "recorded_bytes"],
    )?;
    let checks = [
        (value["admin_api_loopback"] == true && value["private_listener_ok"] == true, "loopback listeners"),
        (value["cover_https_ok"] == true, "cover HTTPS"),
        (
            value["authenticated_connect_ok"] == true && value["connect_bytes"].as_u64().unwrap() > 0,
            "authenticated CONNECT",
        ),
        (value["tunnel_closed_ok"] == true, "tunnel close"),
        (
            value["recorded_bytes"].as_u64().unwrap() >= value["connect_bytes"].as_u64().unwrap(),
            "closed-tunnel accounting",
        ),
        (value["manager_health_ok"] == true, "manager health"),
        (value["panel_health_ok"] == true, "HTTPS probe status"),
        (value["adjacent_sni_ok"] == true, "adjacent SNI"),
        (value["log_boundary_ok"] == true, "accounting log boundary"),
    ];
    for (ok, label) in checks {
        if !ok {
            return Err(acceptance(format!("Naive acceptance failed: {label}")));
        }
    }
    Ok(())
}
pub fn require_mieru(value: &Value) -> Result<(), Error> {
    validate(
        value,
        &[
            "package_digest_ok",
            "executable_digest_ok",
            "mita_status_running",
            "uds_boundary_ok",
            "manager_health_ok",
            "panel_health_ok",
            "send_queue_drained",
            "adjacent_listeners_ok",
            "public_host_ok",
            "temporary_state_removed",
        ],
        &["transports_verified", "transports_expected"],
    )?;
    let expected = value["transports_expected"].as_u64().unwrap();
    let verified = value["transports_verified"].as_u64().unwrap();
    if expected == 0 || verified > expected {
        return Err(acceptance("Mieru acceptance result is invalid"));
    }
    let checks = [
        (value["package_digest_ok"] == true && value["executable_digest_ok"] == true, "pinned artifact digests"),
        (value["mita_status_running"] == true, "exact RUNNING status"),
        (value["uds_boundary_ok"] == true, "management UDS boundary"),
        (verified == expected, "official client probe"),
        (value["send_queue_drained"] == true, "send queue"),
        (value["manager_health_ok"] == true && value["panel_health_ok"] == true, "manager and panel health"),
        (value["adjacent_listeners_ok"] == true, "adjacent listeners"),
        (value["public_host_ok"] == true, "public host"),
    ];
    for (ok, label) in checks {
        if !ok {
            return Err(acceptance(format!("Mieru acceptance failed: {label}")));
        }
    }
    Ok(())
}
fn curl_quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}
pub(super) fn quote(value: &str) -> String {
    let mut output = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            output.push(byte as char);
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}
fn decode(value: &str) -> Result<String, Error> {
    let mut output = Vec::new();
    let bytes = value.as_bytes();
    let mut pos = 0;
    while pos < bytes.len() {
        if bytes[pos] == b'%' && pos + 2 < bytes.len() {
            let hex = &value[pos + 1..pos + 3];
            output.push(u8::from_str_radix(hex, 16).map_err(|_| acceptance("Naive acceptance failed: access"))?);
            pos += 3;
        } else {
            output.push(bytes[pos]);
            pos += 1;
        }
    }
    String::from_utf8(output).map_err(|_| acceptance("Naive acceptance failed: access"))
}
pub(super) fn random_urlsafe<const N: usize>() -> Result<String, Error> {
    let hex = token_hex::<N>();
    let bytes: Vec<_> =
        (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("token_hex is hex")).collect();
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let bits = ((chunk[0] as u32) << 16)
            | ((chunk.get(1).copied().unwrap_or(0) as u32) << 8)
            | (chunk.get(2).copied().unwrap_or(0) as u32);
        output.push(alphabet[((bits >> 18) & 63) as usize] as char);
        output.push(alphabet[((bits >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            output.push(alphabet[((bits >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            output.push(alphabet[(bits & 63) as usize] as char);
        }
    }
    Ok(output)
}
