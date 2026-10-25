//! A one-shot HTTP/1.1 client for a Unix socket: health probes and tests.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ClientResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl ClientResponse {
    pub fn json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// Sends one request and reads the response to the end of the connection.
pub fn request(
    socket: &Path,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    timeout: Duration,
) -> io::Result<ClientResponse> {
    for (name, value) in headers {
        if name.contains(['\r', '\n', ':']) || value.contains(['\r', '\n']) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid header"));
        }
    }
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(body) = body {
        head.push_str(&format!("Content-Type: application/json\r\nContent-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    if let Some(body) = body {
        stream.write_all(body)?;
    }
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> io::Result<ClientResponse> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "malformed response");
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Response::new(&mut headers);
    let head_len = match parsed.parse(raw).map_err(|_| invalid())? {
        httparse::Status::Complete(len) => len,
        httparse::Status::Partial => return Err(invalid()),
    };
    let status = parsed.code.ok_or_else(invalid)?;
    let headers: Vec<(String, String)> =
        parsed.headers.iter().map(|h| (h.name.to_string(), String::from_utf8_lossy(h.value).into_owned())).collect();
    let mut body = raw[head_len..].to_vec();
    if let Some(length) = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
    {
        body.truncate(length);
    }
    Ok(ClientResponse { status, headers, body })
}

/// A plain-HTTP GET to a TCP listener (the loopback metrics endpoints of the proxied services);
/// reads at most `max` body bytes and undoes chunked transfer coding.
pub fn tcp_get(address: &str, path: &str, timeout: Duration, max: usize) -> io::Result<ClientResponse> {
    use std::net::{TcpStream, ToSocketAddrs};
    let target = address
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "address resolves to nothing"))?;
    let mut stream = TcpStream::connect_timeout(&target, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let head = format!("GET {path} HTTP/1.1\r\nHost: {address}\r\nAccept: */*\r\nConnection: close\r\n\r\n");
    stream.write_all(head.as_bytes())?;
    let mut raw = Vec::new();
    stream.take((max + 64 * 1024) as u64).read_to_end(&mut raw)?;
    let mut response = parse_response(&raw)?;
    let chunked =
        response.header("transfer-encoding").is_some_and(|value| value.to_ascii_lowercase().contains("chunked"));
    if chunked {
        response.body = dechunk(&response.body)?;
    }
    response.body.truncate(max);
    Ok(response)
}

fn dechunk(mut data: &[u8]) -> io::Result<Vec<u8>> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "malformed chunked body");
    let mut out = Vec::new();
    loop {
        let line_end = data.windows(2).position(|w| w == b"\r\n").ok_or_else(invalid)?;
        let size_text = std::str::from_utf8(&data[..line_end]).map_err(|_| invalid())?;
        let size_text = size_text.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16).map_err(|_| invalid())?;
        data = &data[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if data.len() < size + 2 {
            return Err(invalid());
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size + 2..];
    }
}

/// The container health probe every manager runs: `GET /v1/health` with the token; healthy
/// when the status is `ok` or one of the `tolerated` `(status, code)` pairs.
pub fn health_probe(socket: &Path, token_file: &Path, header: &str, tolerated: &[(&str, &str)]) -> bool {
    let Ok(token) = crate::read_token(token_file) else { return false };
    let Ok(response) = request(socket, "GET", "/v1/health", &[(header, &token)], None, Duration::from_secs(2)) else {
        return false;
    };
    if response.status != 200 {
        return false;
    }
    let Ok(health) = response.json() else { return false };
    let status = health.get("status").and_then(|v| v.as_str()).unwrap_or("");
    let code = health.get("code").and_then(|v| v.as_str()).unwrap_or("");
    status == "ok" || tolerated.iter().any(|(s, c)| *s == status && *c == code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn serve_once(reply: &'static [u8]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            stream.write_all(reply).unwrap();
        });
        address
    }

    #[test]
    fn tcp_get_reads_plain_and_chunked_bodies() {
        let plain = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]");
        let got = tcp_get(&plain, "/clients", Duration::from_secs(2), 1024).unwrap();
        assert_eq!((got.status, got.body.as_slice()), (200, &b"[]"[..]));
        let chunked =
            serve_once(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n[1,\r\n2\r\n2]\r\n0\r\n\r\n");
        let got = tcp_get(&chunked, "/clients", Duration::from_secs(2), 1024).unwrap();
        assert_eq!(got.json().unwrap(), serde_json::json!([1, 2]));
    }

    #[test]
    fn dechunk_rejects_truncated_bodies() {
        assert!(dechunk(b"5\r\nab").is_err());
        assert!(dechunk(b"zz\r\n").is_err());
    }
}
