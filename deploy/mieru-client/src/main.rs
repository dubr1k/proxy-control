//! Apply the pinned official client's configuration and prove an HTTP status through SOCKS5.
use std::env;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::process::{Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use url::{Host, Position, Url};

const DEADLINE: Duration = Duration::from_secs(60);
const INTERVAL: Duration = Duration::from_millis(400);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

struct Destination {
    host: String,
    port: u16,
    request: String,
}

impl Destination {
    fn parse(value: &str) -> Result<Self, &'static str> {
        let url = Url::parse(value).map_err(|_| "invalid MIERU_PROBE_URL")?;
        if url.scheme() != "http" || !url.username().is_empty() || url.password().is_some() {
            return Err("the probe endpoint must be plain HTTP without credentials");
        }
        let host = match url.host().ok_or("the probe endpoint has no host")? {
            Host::Domain(name) => name.to_owned(),
            Host::Ipv4(address) => address.to_string(),
            Host::Ipv6(address) => address.to_string(),
        };
        if host.len() > u8::MAX as usize {
            return Err("the probe endpoint host exceeds the SOCKS5 name limit");
        }
        let authority = &url[Position::BeforeHost..Position::AfterPort];
        let mut request =
            String::with_capacity(url.path().len() + url.query().map_or(0, str::len) + authority.len() + 96);
        request.push_str("GET ");
        request.push_str(url.path());
        if let Some(query) = url.query() {
            request.push('?');
            request.push_str(query);
        }
        request.push_str(" HTTP/1.1\r\nHost: ");
        request.push_str(authority);
        request.push_str("\r\nConnection: close\r\nUser-Agent: proxy-control-acceptance\r\n\r\n");
        Ok(Self { host, port: url.port_or_known_default().unwrap_or(80), request })
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn drain_socks_reply(reader: &mut impl Read) -> io::Result<()> {
    let mut head = [0; 4];
    reader.read_exact(&mut head)?;
    if head[0] != 5 || head[2] != 0 {
        return Err(invalid("SOCKS5 reply is malformed"));
    }
    if head[1] != 0 {
        return Err(invalid("SOCKS5 connect refused"));
    }
    let length = match head[3] {
        1 => 4,
        3 => {
            let mut length = [0];
            reader.read_exact(&mut length)?;
            usize::from(length[0])
        }
        4 => 16,
        _ => return Err(invalid("SOCKS5 reply is malformed")),
    };
    let mut address = [0; 255];
    reader.read_exact(&mut address[..length])?;
    reader.read_exact(&mut [0; 2])
}

fn negotiate(stream: &mut TcpStream, destination: &Destination) -> io::Result<()> {
    stream.write_all(&[5, 1, 0])?;
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting)?;
    if greeting != [5, 0] {
        return Err(invalid("SOCKS5 greeting refused"));
    }
    let name = destination.host.as_bytes();
    let mut request = [0; 262];
    request[..5].copy_from_slice(&[5, 1, 0, 3, name.len() as u8]);
    request[5..5 + name.len()].copy_from_slice(name);
    request[5 + name.len()..7 + name.len()].copy_from_slice(&destination.port.to_be_bytes());
    stream.write_all(&request[..7 + name.len()])?;
    drain_socks_reply(stream)
}

fn read_status(reader: &mut impl Read) -> io::Result<u16> {
    let mut head = [0; 256];
    let mut length = 0;
    while length < head.len() {
        let end = (length + 64).min(head.len());
        let read = match reader.read(&mut head[length..end]) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if read == 0 {
            break;
        }
        let search_start = length.saturating_sub(1);
        length += read;
        if let Some(end) = head[search_start..length].windows(2).position(|pair| pair == b"\r\n") {
            let line = &head[..search_start + end];
            let mut fields = line.split(|byte| byte.is_ascii_whitespace()).filter(|field| !field.is_empty());
            let protocol = fields.next().unwrap_or_default();
            let status = fields.next().unwrap_or_default();
            if !matches!(protocol, b"HTTP/1.0" | b"HTTP/1.1")
                || status.len() != 3
                || !status.iter().all(u8::is_ascii_digit)
            {
                return Err(invalid("the probe endpoint returned no status line"));
            }
            return Ok(u16::from(status[0] - b'0') * 100
                + u16::from(status[1] - b'0') * 10
                + u16::from(status[2] - b'0'));
        }
    }
    Err(invalid("the probe endpoint returned no status line"))
}

fn status_through(proxies: &[SocketAddr], destination: &Destination, deadline: Instant) -> io::Result<u16> {
    let mut last = io::Error::new(io::ErrorKind::AddrNotAvailable, "no SOCKS5 address");
    for proxy in proxies {
        let timeout = deadline.saturating_duration_since(Instant::now()).min(IO_TIMEOUT);
        if timeout.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "probe deadline"));
        }
        let mut stream = match TcpStream::connect_timeout(proxy, timeout) {
            Ok(stream) => stream,
            Err(error) => {
                last = error;
                continue;
            }
        };
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        negotiate(&mut stream, destination)?;
        stream.write_all(destination.request.as_bytes())?;
        return read_status(&mut stream);
    }
    Err(last)
}

fn run_client(arguments: &[&str]) -> io::Result<bool> {
    // A daemon inherits stdout/stderr. Never capture a pipe it could keep open, or expose the
    // reveal's credentials through client diagnostics. Only command status is needed here.
    let mut child = Command::new("mieru")
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status.success());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(io::ErrorKind::TimedOut, "mieru command timed out"));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

struct StopClient;
impl Drop for StopClient {
    fn drop(&mut self) {
        let _ = run_client(&["stop"]);
    }
}

fn required(name: &'static str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("{name} is required"))
}

fn run() -> Result<(), String> {
    let expected = required("MIERU_PROBE_STATUS")?.parse::<u16>().map_err(|_| "invalid MIERU_PROBE_STATUS")?;
    let destination = Destination::parse(&required("MIERU_PROBE_URL")?)?;
    let proxies: Vec<_> =
        required("MIERU_PROBE_SOCKS")?.to_socket_addrs().map_err(|_| "invalid MIERU_PROBE_SOCKS")?.collect();
    let configuration = required("MIERU_PROBE_CONFIG")?;
    if !run_client(&["apply", "config", &configuration])
        .map_err(|_| "mieru could not apply the client configuration")?
    {
        return Err("mieru could not apply the client configuration".into());
    }
    if !run_client(&["start"]).map_err(|_| "mieru client did not start")? {
        return Err("mieru client did not start".into());
    }
    let _stop = StopClient;
    let deadline = Instant::now() + DEADLINE;
    let mut last_status = None;
    while Instant::now() < deadline {
        match status_through(&proxies, &destination, deadline) {
            Ok(status) if status == expected => return Ok(()),
            Ok(status) => last_status = Some(status),
            Err(_) => last_status = None,
        }
        thread::sleep(INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
    }
    Err(match last_status {
        Some(status) => format!("no probe reached the expected status: status {status}"),
        None => "no probe reached the expected status: OSError".into(),
    })
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct Fragments<R>(R);
    impl<R: Read> Read for Fragments<R> {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let length = output.len().min(1);
            self.0.read(&mut output[..length])
        }
    }

    #[test]
    fn fragmented_socks_addresses_are_drained_before_reading_http() {
        for address in [vec![1, 127, 0, 0, 1], vec![3, 3, b'l', b'a', b'b'], [vec![4], vec![0; 16]].concat()] {
            let mut wire = vec![5, 0, 0];
            wire.extend(address);
            wire.extend([0x1f, 0x90]);
            wire.extend(b"HTTP/1.1 204 No Content\r\n\r\n");
            let mut reader = Fragments(Cursor::new(wire));
            drain_socks_reply(&mut reader).unwrap();
            assert_eq!(read_status(&mut reader).unwrap(), 204);
        }
    }

    #[test]
    fn a_refused_or_malformed_socks_reply_cannot_prove_http_success() {
        for reply in [[5, 5, 0, 1], [4, 0, 0, 1], [5, 0, 1, 1], [5, 0, 0, 9]] {
            let mut wire = reply.to_vec();
            wire.extend(b"HTTP/1.1 204 No Content\r\n");
            assert!(drain_socks_reply(&mut Cursor::new(wire)).is_err());
        }
    }

    #[test]
    fn a_status_needs_a_bounded_complete_http_line() {
        assert_eq!(read_status(&mut Fragments(Cursor::new(b"HTTP/1.0 403 Forbidden\r\n"))).unwrap(), 403);
        for line in [&b"garbage 204 ok\r\n"[..], b"HTTP/1.1 2x4 ok\r\n", b"HTTP/1.1 204", &[b'x'; 257]] {
            assert!(read_status(&mut Cursor::new(line)).is_err());
        }
    }
}
