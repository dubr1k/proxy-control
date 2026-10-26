//! `panel healthcheck` — the compose health check (`compose.yaml:121-134` ran it in bash):
//! `GET /healthz HTTP/1.0` with `Host: $PANEL_HEALTHCHECK_HOST` (default `localhost`) to
//! `127.0.0.1:8787` (or the `PANEL_LISTEN` socket), healthy when the status line is `HTTP/… 200`
//! within 5 s.

use std::io::{BufRead as _, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use crate::server::Listen;

const TIMEOUT: Duration = Duration::from_secs(5);

/// Exit code 0 when healthy, 1 otherwise.
pub fn run() -> i32 {
    let host = std::env::var("PANEL_HEALTHCHECK_HOST").unwrap_or_else(|_| "localhost".to_string());
    let listen = Listen::from_env(std::env::var("PANEL_LISTEN").ok().as_deref())
        .unwrap_or(Listen::Tcp(SocketAddr::from(([0, 0, 0, 0], 8787))));
    match probe(&listen, &host) {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(error) => {
            eprintln!("healthcheck: {error}");
            1
        }
    }
}

/// Whether the panel answers 200 on `/healthz`.
pub fn probe(listen: &Listen, host: &str) -> std::io::Result<bool> {
    let request = format!("GET /healthz HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    let line = match listen {
        Listen::Tcp(address) => {
            let target = SocketAddr::from(([127, 0, 0, 1], address.port()));
            let stream = TcpStream::connect_timeout(&target, TIMEOUT)?;
            exchange(stream, &request)?
        }
        Listen::Unix(path) => exchange(std::os::unix::net::UnixStream::connect(path)?, &request)?,
    };
    let mut words = line.split(' ');
    Ok(words.next().is_some_and(|protocol| protocol.starts_with("HTTP/")) && words.next() == Some("200"))
}

trait Timeouts {
    fn timeouts(&self, timeout: Duration) -> std::io::Result<()>;
}

impl Timeouts for TcpStream {
    fn timeouts(&self, timeout: Duration) -> std::io::Result<()> {
        self.set_read_timeout(Some(timeout))?;
        self.set_write_timeout(Some(timeout))
    }
}

impl Timeouts for std::os::unix::net::UnixStream {
    fn timeouts(&self, timeout: Duration) -> std::io::Result<()> {
        self.set_read_timeout(Some(timeout))?;
        self.set_write_timeout(Some(timeout))
    }
}

fn exchange<S: Read + Write + Timeouts>(mut stream: S, request: &str) -> std::io::Result<String> {
    stream.timeouts(TIMEOUT)?;
    stream.write_all(request.as_bytes())?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line)?;
    Ok(line.trim_end().to_string())
}
