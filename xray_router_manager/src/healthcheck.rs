//! Minimal authenticated probes of the manager's socket: the health check the container runs
//! (`xray-router-manager healthcheck`), and `--status`, `--relay`, `--relay-enable` for the
//! installer's verification (`docker exec`). The JSON body goes to stdout as the manager sent it.

use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use crate::util::{py_decimal, py_int};

pub const USAGE: &str =
    "usage: xray-router-manager healthcheck [--status | --relay | --relay-enable <server_name> <port>]";

/// The body of a 200 answer, or `None` for anything else (no socket, a bad token, another status).
fn request(
    socket: &Path,
    token_file: &Path,
    method: &str,
    target: &str,
    body: Option<&[u8]>,
    timeout: Duration,
) -> Option<Vec<u8>> {
    let token = pc_common::read_token(token_file).ok()?;
    let headers = [(crate::server::TOKEN_HEADER, token.as_str())];
    let response = pc_common::client::request(socket, method, target, &headers, body, timeout).ok()?;
    (response.status == 200).then_some(response.body)
}

pub fn check(socket: &Path, token_file: &Path) -> bool {
    request(socket, token_file, "GET", "/v1/health", None, Duration::from_secs(2)).is_some()
}

/// The exit status and what to print, for the arguments after `healthcheck`.
pub fn run(arguments: &[String], env: &HashMap<String, String>) -> (i32, Option<Vec<u8>>, Option<String>) {
    let socket = env.get("XRAY_ROUTER_SOCKET").cloned().unwrap_or_else(|| "/run/xray-router/manager.sock".into());
    let token = env
        .get("XRAY_ROUTER_MANAGER_TOKEN_FILE")
        .cloned()
        .unwrap_or_else(|| "/run/secrets/xray-router-manager-token".into());
    let (socket, token) = (Path::new(&socket), Path::new(&token));
    let args: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let body = match args.as_slice() {
        [] => return (if check(socket, token) { 0 } else { 1 }, None, None),
        ["--status"] => request(socket, token, "GET", "/v1/status", None, Duration::from_secs(5)),
        ["--relay"] => request(socket, token, "GET", "/v1/relay", None, Duration::from_secs(5)),
        ["--relay-enable", server_name, port] if !port.is_empty() && port.chars().all(|c| py_decimal(c).is_some()) => {
            // `POST /v1/relay` (v0.7): the inbound up on `port` with the node's own panel name as
            // its cover; the keypair is minted once, by the manager.
            let port = py_int(port, 10).unwrap_or(0);
            let payload = serde_json::json!({"server_name": server_name, "port": port as i64});
            let payload = crate::pyjson::dumps(&payload, &crate::pyjson::DEFAULT);
            request(socket, token, "POST", "/v1/relay", Some(payload.as_bytes()), Duration::from_secs(30))
        }
        _ => return (1, None, Some(USAGE.into())),
    };
    match body {
        Some(mut body) => {
            body.push(b'\n');
            (0, Some(body), None)
        }
        None => (1, None, None),
    }
}

pub fn main(arguments: &[String]) -> i32 {
    let env: HashMap<String, String> = std::env::vars().collect();
    let (code, stdout, stderr) = run(arguments, &env);
    if let Some(out) = stdout {
        let _ = std::io::stdout().lock().write_all(&out);
    }
    if let Some(message) = stderr {
        eprintln!("{message}");
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::net::UnixListener;

    /// A one-shot manager stand-in: records each request and answers like the Python tests'
    /// fake (HTTP/1.0, no length, close).
    fn serve(
        dir: &Path,
        answers: usize,
        body: &'static [u8],
    ) -> (std::thread::JoinHandle<Vec<Vec<u8>>>, HashMap<String, String>) {
        let socket = dir.join("manager.sock");
        let _ = std::fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket).unwrap();
        let token = dir.join("token");
        std::fs::write(&token, format!("{}\n", "t".repeat(40))).unwrap();
        let thread = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for _ in 0..answers {
                let (mut client, _) = listener.accept().unwrap();
                let mut buf = vec![0u8; 4096];
                let n = client.read(&mut buf).unwrap();
                seen.push(buf[..n].to_vec());
                let mut reply = b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n".to_vec();
                reply.extend_from_slice(body);
                client.write_all(&reply).unwrap();
            }
            seen
        });
        let env = [
            ("XRAY_ROUTER_SOCKET".to_string(), socket.display().to_string()),
            ("XRAY_ROUTER_MANAGER_TOKEN_FILE".to_string(), token.display().to_string()),
        ]
        .into();
        (thread, env)
    }

    fn tempdir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("xr-hc-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Ported from `tests/test_installer_xray_router.py`: `docker exec … healthcheck --status` is
    /// what the installer's verify parses.
    #[test]
    fn healthcheck_status_flag_prints_the_manager_status() {
        let dir = tempdir("status");
        let (thread, env) = serve(&dir, 1, br#"{"phase": "idle", "running": {"generation": 1}}"#);
        let (code, out, _) = run(&["--status".to_string()], &env);
        assert_eq!(code, 0);
        let printed: serde_json::Value = serde_json::from_slice(&out.unwrap()).unwrap();
        assert_eq!(printed["phase"], "idle");
        let seen = thread.join().unwrap();
        let request = String::from_utf8_lossy(&seen[0]);
        assert!(request.starts_with("GET /v1/status HTTP/1.1\r\n"), "{request}");
        assert!(request.contains(&format!("X-Xray-Router-Token: {}", "t".repeat(40))));
    }

    /// Ported from `tests/test_installer_chains.py`.
    #[test]
    fn healthcheck_relay_flags_post_and_get() {
        let dir = tempdir("relay");
        let (thread, env) = serve(&dir, 2, br#"{"enabled": true, "port": 45443}"#);
        let (code, out, _) = run(&["--relay-enable".into(), "panel.example.com".into(), "45443".into()], &env);
        assert_eq!(code, 0);
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&out.unwrap()).unwrap()["port"], 45443);
        let (code, out, _) = run(&["--relay".into()], &env);
        assert_eq!(code, 0);
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&out.unwrap()).unwrap()["enabled"], true);
        let seen = thread.join().unwrap();
        let post = String::from_utf8_lossy(&seen[0]);
        assert!(post.starts_with("POST /v1/relay HTTP/1.1\r\n"), "{post}");
        assert!(post.ends_with(r#"{"server_name": "panel.example.com", "port": 45443}"#), "{post}");
        assert!(String::from_utf8_lossy(&seen[1]).starts_with("GET /v1/relay HTTP/1.1\r\n"));
        // anything else is the usage line, and no answer is exit 1
        let (code, _, err) = run(&["--relay-enable".into(), "x".into(), "port".into()], &env);
        assert_eq!((code, err.as_deref()), (1, Some(USAGE)));
        assert_eq!(run(&["--status".into()], &env).0, 1);
    }
}
