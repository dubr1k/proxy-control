use super::*;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreAcceptance {
    pub compose_config_ok: bool,
    pub healthy_services: usize,
    pub expected_services: usize,
    pub panel_health_ok: bool,
    pub panel_login_ok: bool,
    pub telemt_api_internal: bool,
    pub respq_verified: usize,
    pub respq_expected: usize,
    pub adjacent_sni_ok: bool,
    pub sensitive_scan_ok: bool,
    pub temporary_state_removed: bool,
}
impl CoreAcceptance {
    pub fn details(&self) -> Map<String, Value> {
        serde_json::from_value(serde_json::to_value(self).expect("acceptance facts serialize"))
            .expect("acceptance facts are an object")
    }
}
pub(super) fn require_acceptance(value: &CoreAcceptance) -> Result<(), Error> {
    if value.expected_services == 0
        || value.respq_expected == 0
        || value.healthy_services > value.expected_services
        || value.respq_verified > value.respq_expected
    {
        return Err(Error::other("ValueError", "acceptance counts are inconsistent"));
    }
    for (ok, label) in [
        (value.compose_config_ok, "Compose config"),
        (value.healthy_services == value.expected_services, "Compose health checks"),
        (value.panel_health_ok, "panel health"),
        (value.panel_login_ok, "panel login"),
        (value.telemt_api_internal, "Telemt API isolation"),
        (value.respq_verified == value.respq_expected, "resPQ"),
        (value.adjacent_sni_ok, "adjacent SNI"),
        (value.sensitive_scan_ok, "sensitive scan"),
        (value.temporary_state_removed, "temporary-user cleanup"),
    ] {
        if !ok {
            return Err(acceptance(format!("Core acceptance failed: {label}")));
        }
    }
    Ok(())
}

pub(crate) struct PanelSession {
    client: HttpsClient,
    domain: String,
    cookies: BTreeMap<String, String>,
}
impl PanelSession {
    pub(crate) fn request(
        &mut self,
        method: &str,
        path: &str,
        payload: Option<Value>,
        csrf: bool,
        json: bool,
    ) -> Result<Value, Error> {
        let url = format!("https://{}{path}", self.domain);
        let cookie = self.cookies.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ");
        let token = self.cookies.get("panel_csrf").cloned().unwrap_or_default();
        let mut headers = vec![("Cookie", cookie.as_str())];
        if csrf {
            headers.push(("X-CSRF-Token", token.as_str()));
        }
        let body = payload.map(|value| serde_json::to_vec(&value).expect("JSON value serializes"));
        if body.is_some() {
            headers.push(("Content-Type", "application/json"));
        }
        let response = self
            .client
            .request(
                &HttpsRequest {
                    method,
                    url: &url,
                    headers: &headers,
                    body: body.as_deref(),
                    redirects: Redirects::Return,
                },
                &[&self.domain],
                MAX_RESPONSE_BYTES,
            )
            .map_err(|error| match error {
                NetError::TooLarge => acceptance("Core acceptance response is too large"),
                _ => acceptance(format!("panel request {method} {path} did not complete")),
            })?;
        if !(200..300).contains(&response.status()) {
            return Err(acceptance(format!("panel request {method} {path} returned {}", response.status())));
        }
        for (_, raw) in response.head.raw_headers.iter().filter(|(name, _)| name == "set-cookie") {
            if let Some((name, value)) = raw.split(';').next().unwrap_or("").split_once('=') {
                if matches!(name, "panel_csrf" | "panel_session") {
                    self.cookies.insert(name.into(), value.into());
                }
            }
        }
        if !json || response.body.is_empty() {
            return Ok(json!({}));
        }
        serde_json::from_slice(&response.body).map_err(|_| acceptance("Core acceptance response is invalid"))
    }
    pub(crate) fn logout(&mut self) -> Result<(), Error> {
        self.request("POST", "/api/auth/logout", None, true, false).map(|_| ())
    }
    pub(crate) fn login(domain: &str, password: &str) -> Result<Self, Error> {
        let client = HttpsClient::new(ClientOptions {
            user_agent: String::new(),
            timeout: Duration::from_secs(20),
            max_redirects: 0,
            roots: Roots::System,
        })
        .map_err(|_| acceptance("Core acceptance failed: panel login"))?;
        let mut session = Self { client, domain: domain.into(), cookies: BTreeMap::new() };
        let result = (|| {
            session.request("GET", "/login", None, false, false)?;
            if session.cookies.get("panel_csrf").is_none_or(String::is_empty) {
                return Err(acceptance("Core acceptance failed: panel login"));
            }
            session.request(
                "POST",
                "/api/auth/login",
                Some(json!({"username":"owner", "password":password})),
                true,
                false,
            )?;
            if session.cookies.get("panel_csrf").is_none_or(String::is_empty) {
                return Err(acceptance("Core acceptance failed: panel login"));
            }
            Ok(())
        })();
        if let Err(error) = result {
            if session.cookies.contains_key("panel_csrf") && session.logout().is_err() {
                return Err(acceptance("Core acceptance failed: session cleanup"));
            }
            return Err(error);
        }
        Ok(session)
    }
    fn has_user(&mut self, name: &str) -> Result<bool, Error> {
        let users = self.request("GET", "/api/users", None, false, true)?;
        Ok(users
            .get("items")
            .and_then(Value::as_array)
            .is_some_and(|rows| rows.iter().any(|row| row.get("username").and_then(Value::as_str) == Some(name))))
    }
}

impl CoreAdapter {
    fn acceptance_command(&self, argv: &[&str], label: &str) -> Result<(), Error> {
        let result = self.runner.run(argv, &RunOptions::default())?;
        if result.returncode != 0 {
            let detail = sanitize_diagnostic(&String::from_utf8_lossy(&result.stderr), 900);
            return Err(acceptance(if detail.is_empty() {
                format!("Core acceptance failed: {label}")
            } else {
                format!("Core acceptance failed: {label}: {detail}")
            }));
        }
        Ok(())
    }
    fn acceptance_session(&self, selected: &Selection) -> Result<PanelSession, Error> {
        let password = fs::read_to_string(self.host(&format!("{PROJECT}/secrets/panel-bootstrap-password"))?)?;
        PanelSession::login(&selected.panel_domain, password.trim_end_matches(['\r', '\n']))
    }
    pub(super) fn cleanup_acceptance(&self, selected: &Selection, name: &str) -> Result<(), Error> {
        #[cfg(test)]
        if let Some(mock) = &self.test_acceptance {
            return mock.cleanup();
        }
        let mut session = self.acceptance_session(selected)?;
        let result = (|| {
            if session.has_user(name)? {
                session.request("DELETE", &format!("/api/users/{name}"), None, true, true)?;
            }
            Ok(())
        })();
        let logout = session.logout();
        result.and(logout)
    }
    pub(super) fn run_acceptance(
        &self,
        selected: &Selection,
        name: &str,
        recover: bool,
    ) -> Result<CoreAcceptance, Error> {
        #[cfg(test)]
        if let Some(mock) = &self.test_acceptance {
            return mock.run(selected.users.len());
        }
        let compose = self.compose_argv(&["config", "-q"])?;
        self.acceptance_command(&compose.iter().map(String::as_str).collect::<Vec<_>>(), "Compose config")?;
        let argv = self.compose_argv(&["ps", "--format", "json"])?;
        let output = self.capture_checked(&argv.iter().map(String::as_str).collect::<Vec<_>>())?;
        let healthy = healthy_services(&output)?;
        self.panel_health(&selected.panel_domain)?;
        let count = self.panel_and_respq(selected, name, recover)?;
        if count != selected.users.len() + 1 {
            return Err(acceptance("Core acceptance failed: resPQ"));
        }
        self.verify_adjacent(&selected.adjacent_sni)?;
        Ok(CoreAcceptance {
            compose_config_ok: true,
            healthy_services: healthy,
            expected_services: 3,
            panel_health_ok: true,
            panel_login_ok: true,
            telemt_api_internal: !compose_publishes_telemt_api(&fs::read_to_string(self.tree.join("compose.yaml"))?),
            respq_verified: count,
            respq_expected: count,
            adjacent_sni_ok: true,
            sensitive_scan_ok: self.bounded_sensitive_scan(),
            temporary_state_removed: true,
        })
    }
    fn panel_and_respq(&self, selected: &Selection, name: &str, recover: bool) -> Result<usize, Error> {
        let users = self.host(&format!("{PROJECT}/secrets/users.conf"))?;
        let configured = fs::read_to_string(&users)?;
        if !valid_users_file(&configured) {
            return Err(acceptance("Core acceptance failed: resPQ"));
        }
        let probe = self.host(PROBE)?;
        self.acceptance_command(
            &[&probe.to_string_lossy(), "--domain", &selected.proxy_domain, "--secrets-file", &users.to_string_lossy()],
            "resPQ",
        )?;
        let mut session = self.acceptance_session(selected)?;
        let mut created = false;
        let mut temporary_created = false;
        let temporary = std::env::temp_dir().join(format!("proxy-control-respq-{}", token_hex::<16>()));
        let result = (|| {
            let me = session.request("GET", "/api/auth/me", None, false, true)?;
            if me.get("username").and_then(Value::as_str) != Some("owner") {
                return Err(acceptance("Core acceptance failed: panel login"));
            }
            if session.has_user(name)? {
                if !recover {
                    return Err(collision());
                }
                session.request("DELETE", &format!("/api/users/{name}"), None, true, true)?;
            }
            let response = session.request("POST", "/api/users", Some(json!({"username":name})), true, true)?;
            created = true;
            let reveal = response
                .get("reveal_token")
                .and_then(Value::as_str)
                .filter(|token| {
                    !token.is_empty() && token.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
                })
                .ok_or_else(|| acceptance("Core acceptance failed: resPQ"))?;
            let credential = session.request("GET", &format!("/api/reveal/{reveal}"), None, false, true)?;
            let secret = credential
                .get("secret")
                .and_then(Value::as_str)
                .filter(|value| is_hex(value, 32))
                .ok_or_else(|| acceptance("Core acceptance failed: resPQ"))?;
            let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temporary)?;
            temporary_created = true;
            writeln!(file, "{name}={secret}")?;
            file.sync_all()?;
            self.acceptance_command(
                &[
                    &probe.to_string_lossy(),
                    "--domain",
                    &selected.proxy_domain,
                    "--secrets-file",
                    &temporary.to_string_lossy(),
                ],
                "resPQ",
            )?;
            Ok(configured.lines().count() + 1)
        })();
        let mut cleanup = Ok(());
        if created {
            cleanup = session.request("DELETE", &format!("/api/users/{name}"), None, true, true).map(|_| ());
        }
        let logout = session.logout();
        let remove = if temporary_created {
            match fs::remove_file(&temporary) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error.into()),
            }
        } else {
            Ok(())
        };
        cleanup.and(logout).and(remove)?;
        result
    }
    fn panel_health_failure(&self, status: Option<u16>) -> Error {
        let mut message = "Core acceptance failed: panel health".to_string();
        if let Some(status) = status {
            message.push_str(&format!(" (status {status})"));
        }
        for (label, extra) in [
            ("services", vec!["ps", "--format", "{{.Service}}: {{.State}} {{.Status}}"]),
            ("panel", vec!["logs", "--tail", "80", "panel"]),
        ] {
            if let Ok(argv) = self.compose_argv(&extra) {
                let captured =
                    self.runner.capture(&argv.iter().map(String::as_str).collect::<Vec<_>>(), 6000, Capture::CORE);
                let filtered = captured
                    .lines()
                    .filter(|line| !line.contains("\"GET /healthz HTTP/1.0\" 200"))
                    .collect::<Vec<_>>()
                    .join("\n");
                let diagnostic = sanitize_diagnostic(&filtered, 900);
                if !diagnostic.is_empty() {
                    message.push_str(&format!("; {label}: {diagnostic}"));
                }
            }
        }
        acceptance(message)
    }
    fn panel_health(&self, domain: &str) -> Result<(), Error> {
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            let result = (|| -> io::Result<(u16, bool)> {
                let mut socket = TcpStream::connect_timeout(
                    &SocketAddr::from(([127, 0, 0, 1], PANEL_APP_PORT)),
                    Duration::from_secs(2),
                )?;
                socket.set_read_timeout(Some(Duration::from_secs(2)))?;
                socket.set_write_timeout(Some(Duration::from_secs(2)))?;
                write!(socket, "GET /healthz HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n")?;
                let mut bytes = Vec::new();
                socket.take(65_537 + 16_384).read_to_end(&mut bytes)?;
                let Some(split) = bytes.windows(4).position(|w| w == b"\r\n\r\n") else {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid panel health response"));
                };
                let status = std::str::from_utf8(&bytes[..split])
                    .ok()
                    .and_then(|head| head.lines().next()?.split_whitespace().nth(1)?.parse::<u16>().ok())
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid panel health status"))?;
                Ok((status, bytes.len() - split - 4 <= 65_536))
            })();
            match result {
                Ok((200, true)) => return Ok(()),
                Ok((status, _)) => return Err(self.panel_health_failure(Some(status))),
                Err(_) if Instant::now() >= deadline => return Err(self.panel_health_failure(None)),
                Err(_) => {}
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    pub(crate) fn verify_adjacent(&self, expected: &[(String, String)]) -> Result<(), Error> {
        if expected.is_empty() {
            return Ok(());
        }
        let text = self.capture_checked(&["nginx", "-T"])?;
        let observed = super::super::nginx::active_sni_routes(&text)
            .map_err(|_| acceptance("Core acceptance failed: adjacent SNI mapping"))?;
        for (domain, backend) in expected {
            if !observed.get(domain).is_some_and(|value| backend == "audited" || value == backend) {
                return Err(acceptance("Core acceptance failed: adjacent SNI mapping"));
            }
            let report = self.runner.run(
                &[
                    "openssl",
                    "s_client",
                    "-connect",
                    "127.0.0.1:443",
                    "-servername",
                    domain,
                    "-verify_hostname",
                    domain,
                    "-verify_return_error",
                    "-brief",
                ],
                &RunOptions::default(),
            )?;
            let report = String::from_utf8_lossy(&report.stderr);
            if !report.contains("Verification: OK") || !report.contains(&format!("Verified peername: {domain}")) {
                return Err(acceptance("Core acceptance failed: adjacent SNI"));
            }
        }
        Ok(())
    }
}
fn healthy_services(output: &str) -> Result<usize, Error> {
    let failure = || acceptance("Core acceptance failed: Compose health checks");
    let records = match serde_json::from_str::<Value>(output) {
        Ok(Value::Array(rows)) => rows,
        Ok(value) => vec![value],
        Err(_) => output
            .lines()
            .filter(|line| !line.is_empty())
            .map(serde_json::from_str)
            .collect::<Result<Vec<Value>, _>>()
            .map_err(|_| failure())?,
    };
    let required = ["mask", "mtproxy", "panel"];
    let mut seen = BTreeSet::new();
    for row in records {
        let service = row.get("Service").and_then(Value::as_str).ok_or_else(failure)?;
        let state = row.get("State").and_then(Value::as_str).ok_or_else(failure)?;
        let health = row.get("Health").and_then(Value::as_str).ok_or_else(failure)?;
        if !seen.insert(service.to_string())
            || (!required.contains(&service) && !ADJACENT_SERVICES.contains(&service))
            || (required.contains(&service)
                && (!state.eq_ignore_ascii_case("running") || !health.eq_ignore_ascii_case("healthy")))
        {
            return Err(failure());
        }
    }
    if required.iter().any(|service| !seen.contains(*service)) {
        return Err(failure());
    }
    Ok(3)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compose_health_requires_all_core_and_rejects_unknown_or_duplicates() {
        let rows = json!([{"Service":"mask","State":"running","Health":"healthy"},{"Service":"mtproxy","State":"running","Health":"healthy"},{"Service":"panel","State":"running","Health":"healthy"}]);
        assert_eq!(healthy_services(&rows.to_string()).unwrap(), 3);
        let mut rows = rows.as_array().unwrap().clone();
        rows.push(rows[0].clone());
        assert!(healthy_services(&serde_json::to_string(&rows).unwrap()).is_err());
        assert!(healthy_services("[]").is_err());
    }
    #[test]
    fn acceptance_checks_every_fact() {
        let value = CoreAcceptance {
            compose_config_ok: true,
            healthy_services: 3,
            expected_services: 3,
            panel_health_ok: true,
            panel_login_ok: true,
            telemt_api_internal: true,
            respq_verified: 2,
            respq_expected: 2,
            adjacent_sni_ok: true,
            sensitive_scan_ok: true,
            temporary_state_removed: true,
        };
        require_acceptance(&value).unwrap();
        for key in [
            "compose_config_ok",
            "panel_health_ok",
            "panel_login_ok",
            "telemt_api_internal",
            "adjacent_sni_ok",
            "sensitive_scan_ok",
            "temporary_state_removed",
        ] {
            let mut json = serde_json::to_value(&value).unwrap();
            json[key] = Value::Bool(false);
            assert!(require_acceptance(&serde_json::from_value(json).unwrap()).is_err());
        }
    }
}
