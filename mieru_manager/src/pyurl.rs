//! `urllib.parse` as the manager used it: `quote(s, safe="")`, `urlencode` and the parts of
//! `urlsplit` that read a provider's `socks5://host:port`.

const ALWAYS_SAFE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-~";

fn encode(text: &str, plus_for_space: bool) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if ALWAYS_SAFE.contains(&byte) {
            out.push(byte as char);
        } else if byte == b' ' && plus_for_space {
            out.push('+');
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// `urllib.parse.quote(text, safe="")`.
pub fn quote(text: &str) -> String {
    encode(text, false)
}

/// `urllib.parse.urlencode(pairs)` (`quote_plus` on keys and values).
pub fn urlencode(pairs: &[(&str, String)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| format!("{}={}", encode(key, true), encode(value, true)))
        .collect::<Vec<_>>()
        .join("&")
}

/// The scheme, host and port of a URL as `urlsplit` reports them (`scheme` and `hostname`
/// lowercased, brackets stripped, the zone id kept). `Err` where reading `.port` raises.
#[derive(Debug, PartialEq, Eq)]
pub struct Split {
    pub scheme: String,
    pub hostname: Option<String>,
    pub port: Option<u32>,
}

pub fn urlsplit(url: &str) -> Result<Split, String> {
    // WHATWG: leading C0 controls and spaces go, tabs and line breaks anywhere go.
    let url: String =
        url.trim_start_matches(|c: char| c <= ' ').chars().filter(|c| !matches!(c, '\t' | '\r' | '\n')).collect();
    let mut rest = url.as_str();
    let mut scheme = String::new();
    if let Some(colon) = rest.find(':') {
        let candidate = &rest[..colon];
        let valid = candidate.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && candidate.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
        if colon > 0 && valid {
            scheme = candidate.to_ascii_lowercase();
            rest = &rest[colon + 1..];
        }
    }
    let netloc = match rest.strip_prefix("//") {
        Some(after) => {
            let end = after.find(['/', '?', '#']).unwrap_or(after.len());
            &after[..end]
        }
        None => "",
    };
    if netloc.contains('[') != netloc.contains(']') {
        return Err("Invalid IPv6 URL".into());
    }
    let hostinfo = netloc.rsplit_once('@').map_or(netloc, |(_, host)| host);
    let (hostname, port) = match hostinfo.split_once('[') {
        Some((_, bracketed)) => {
            let (host, after) = bracketed.split_once(']').unwrap_or((bracketed, ""));
            (host, after.split_once(':').map_or("", |(_, port)| port))
        }
        None => match hostinfo.split_once(':') {
            Some((host, port)) => (host, port),
            None => (hostinfo, ""),
        },
    };
    let hostname = (!hostname.is_empty()).then(|| match hostname.split_once('%') {
        Some((host, zone)) => format!("{}%{zone}", host.to_lowercase()),
        None => hostname.to_lowercase(),
    });
    let port = if port.is_empty() {
        None
    } else if port.bytes().all(|b| b.is_ascii_digit()) {
        let value = port.trim_start_matches('0');
        let value: u64 = if value.is_empty() { 0 } else { value.parse().map_err(|_| "Port out of range 0-65535")? };
        if value > 65535 {
            return Err("Port out of range 0-65535".into());
        }
        Some(value as u32)
    } else {
        return Err("Port could not be cast to integer value".into());
    };
    Ok(Split { scheme, hostname, port })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlsplit_reads_provider_endpoints() {
        let split = urlsplit("SOCKS5://User:Pw@127.0.0.1:45000/x").unwrap();
        assert_eq!(split, Split { scheme: "socks5".into(), hostname: Some("127.0.0.1".into()), port: Some(45000) });
        let v6 = urlsplit("socks5h://[FE80::1%Eth0]:1080").unwrap();
        assert_eq!((v6.hostname.as_deref(), v6.port), (Some("fe80::1%Eth0"), Some(1080)));
        assert_eq!(urlsplit("http://127.0.0.1:8118").unwrap().scheme, "http");
        assert_eq!(urlsplit("socks5://host").unwrap().port, None);
        assert!(urlsplit("socks5://host:99999").is_err());
        assert!(urlsplit("socks5://host:x1").is_err());
        assert_eq!(urlsplit("127.0.0.1:45000").unwrap().scheme, "");
    }
}
