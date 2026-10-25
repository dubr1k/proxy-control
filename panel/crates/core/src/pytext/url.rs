//! `urllib.parse.urlsplit` of CPython 3.13 and the `hostname`/`port`/`username`/`password`
//! properties of its result.

use super::{ip_address, IpAddress, PyValueError};

/// `urlsplit(url)`'s five components (`SplitResult`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SplitResult {
    pub scheme: String,
    pub netloc: String,
    pub path: String,
    pub query: String,
    pub fragment: String,
}

const SCHEME_CHARS: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-.";

/// `urllib.parse.urlsplit(url)` (default scheme `''`, fragments allowed): leading C0 controls and
/// spaces stripped, tabs and line breaks removed, `ValueError` on unbalanced or invalid brackets
/// and on a netloc that NFKC turns into URL syntax.
pub fn urlsplit(url: &str) -> Result<SplitResult, PyValueError> {
    let mut url: String =
        url.trim_start_matches(|c: char| c <= ' ').chars().filter(|c| !matches!(c, '\t' | '\r' | '\n')).collect();
    let mut result = SplitResult::default();
    if let Some(colon) = url.find(':') {
        let candidate = &url[..colon];
        let first = candidate.chars().next();
        if colon > 0
            && first.is_some_and(|c| c.is_ascii_alphabetic())
            && candidate.chars().all(|c| SCHEME_CHARS.contains(c))
        {
            result.scheme = candidate.to_ascii_lowercase();
            url = url[colon + 1..].to_string();
        }
    }
    if url.starts_with("//") {
        let rest = &url[2..];
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        result.netloc = rest[..end].to_string();
        url = rest[end..].to_string();
        let open = result.netloc.contains('[');
        let close = result.netloc.contains(']');
        if open != close {
            return Err(PyValueError("Invalid IPv6 URL".into()));
        }
        if open && close {
            check_bracketed_netloc(&result.netloc)?;
        }
    }
    if let Some((before, fragment)) = url.split_once('#') {
        result.fragment = fragment.to_string();
        url = before.to_string();
    }
    if let Some((before, query)) = url.split_once('?') {
        result.query = query.to_string();
        url = before.to_string();
    }
    check_netloc(&result.netloc)?;
    result.path = url;
    Ok(result)
}

fn check_bracketed_netloc(netloc: &str) -> Result<(), PyValueError> {
    let host_and_port = netloc.rsplit_once('@').map_or(netloc, |(_, host)| host);
    let hostname = match host_and_port.split_once('[') {
        Some((before, bracketed)) => {
            if !before.is_empty() {
                return Err(PyValueError("Invalid IPv6 URL".into()));
            }
            let (hostname, port) = bracketed.split_once(']').unwrap_or((bracketed, ""));
            if !port.is_empty() && !port.starts_with(':') {
                return Err(PyValueError("Invalid IPv6 URL".into()));
            }
            hostname
        }
        None => host_and_port.split_once(':').map_or(host_and_port, |(host, _)| host),
    };
    check_bracketed_host(hostname)
}

fn check_bracketed_host(hostname: &str) -> Result<(), PyValueError> {
    if let Some(rest) = hostname.strip_prefix('v') {
        // `\Av[a-fA-F0-9]+\..+\Z` (no newline can be left in the URL by now).
        let valid = rest.split_once('.').is_some_and(|(hex, tail)| {
            !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()) && !tail.is_empty()
        });
        if !valid {
            return Err(PyValueError("IPvFuture address is invalid".into()));
        }
        return Ok(());
    }
    match ip_address(hostname)? {
        IpAddress::V4(_) => Err(PyValueError("An IPv4 address cannot be in brackets".into())),
        IpAddress::V6(..) => Ok(()),
    }
}

fn check_netloc(netloc: &str) -> Result<(), PyValueError> {
    if netloc.is_empty() || netloc.is_ascii() {
        return Ok(());
    }
    let stripped: String = netloc.chars().filter(|c| !matches!(c, '@' | ':' | '#' | '?')).collect();
    let normalized = super::nfkc(&stripped);
    if normalized == stripped {
        return Ok(());
    }
    if normalized.contains(['/', '?', '#', '@', ':']) {
        return Err(PyValueError(format!("netloc '{netloc}' contains invalid characters under NFKC normalization")));
    }
    Ok(())
}

impl SplitResult {
    fn userinfo(&self) -> Option<&str> {
        self.netloc.rsplit_once('@').map(|(userinfo, _)| userinfo)
    }

    fn hostinfo(&self) -> (&str, Option<&str>) {
        let hostinfo = self.netloc.rsplit_once('@').map_or(self.netloc.as_str(), |(_, host)| host);
        let (hostname, port) = match hostinfo.split_once('[') {
            Some((_, bracketed)) => {
                let (hostname, after) = bracketed.split_once(']').unwrap_or((bracketed, ""));
                (hostname, after.split_once(':').map_or("", |(_, port)| port))
            }
            None => hostinfo.split_once(':').unwrap_or((hostinfo, "")),
        };
        (hostname, (!port.is_empty()).then_some(port))
    }

    /// `.username`: the text before `:` in the userinfo, `None` without `@`.
    pub fn username(&self) -> Option<&str> {
        self.userinfo().map(|userinfo| userinfo.split_once(':').map_or(userinfo, |(user, _)| user))
    }

    /// `.password`: the text after the first `:` in the userinfo, `None` without one.
    pub fn password(&self) -> Option<&str> {
        self.userinfo().and_then(|userinfo| userinfo.split_once(':').map(|(_, password)| password))
    }

    /// `.hostname`: lower-cased (the `%zone` of a scoped IPv6 address kept as is), `None` when empty.
    pub fn hostname(&self) -> Option<String> {
        let (hostname, _) = self.hostinfo();
        if hostname.is_empty() {
            return None;
        }
        Some(match hostname.split_once('%') {
            Some((host, zone)) => format!("{}%{zone}", host.to_lowercase()),
            None => hostname.to_lowercase(),
        })
    }

    /// `.port`: `Ok(None)` without a port, `ValueError` for a non-numeric one or one above 65535.
    pub fn port(&self) -> Result<Option<u16>, PyValueError> {
        let (_, port) = self.hostinfo();
        let Some(port) = port else { return Ok(None) };
        if !port.bytes().all(|b| b.is_ascii_digit()) {
            return Err(PyValueError(format!("Port could not be cast to integer value as {}", super::repr(port))));
        }
        let value: u64 =
            port.trim_start_matches('0').parse().unwrap_or(if port.bytes().all(|b| b == b'0') { 0 } else { u64::MAX });
        u16::try_from(value).map(Some).map_err(|_| PyValueError("Port out of range 0-65535".into()))
    }
}
