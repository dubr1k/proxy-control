//! The parts of Python 3.12's `ipaddress` the configuration uses: `IPv4Address(text)` (strict
//! dotted quad, no leading zeros), `IPv6Address(text)` and `ip_address(text)`, each with the
//! normalised `str()` and Python's error texts. Golden vectors: `vectors/ipaddress.json`.

use crate::pystr::py_repr;

/// `str(IPv4Address(text))`, or the `AddressValueError` text.
pub fn ipv4_address(text: &str) -> Result<String, String> {
    if text.contains('/') {
        return Err(format!("Unexpected '/' in {}", py_repr(text)));
    }
    ipv4_int(text).map(ipv4_str)
}

fn ipv4_str(value: u32) -> String {
    let [a, b, c, d] = value.to_be_bytes();
    format!("{a}.{b}.{c}.{d}")
}

fn ipv4_int(text: &str) -> Result<u32, String> {
    if text.is_empty() {
        return Err("Address cannot be empty".into());
    }
    let octets: Vec<&str> = text.split('.').collect();
    if octets.len() != 4 {
        return Err(format!("Expected 4 octets in {}", py_repr(text)));
    }
    let mut value = 0u32;
    for octet in octets {
        let parsed = parse_octet(octet).map_err(|err| format!("{err} in {}", py_repr(text)))?;
        value = (value << 8) | parsed;
    }
    Ok(value)
}

fn parse_octet(octet: &str) -> Result<u32, String> {
    if octet.is_empty() {
        return Err("Empty octet not permitted".into());
    }
    if !octet.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("Only decimal digits permitted in {}", py_repr(octet)));
    }
    if octet.len() > 3 {
        return Err(format!("At most 3 characters permitted in {}", py_repr(octet)));
    }
    if octet != "0" && octet.starts_with('0') {
        return Err(format!("Leading zeros are not permitted in {}", py_repr(octet)));
    }
    let value: u32 = octet.parse().expect("1-3 ASCII digits");
    if value > 255 {
        return Err(format!("Octet {value} (> 255) not permitted"));
    }
    Ok(value)
}

/// `str(IPv6Address(text))` (with `%scope` kept), or the `AddressValueError` text.
pub fn ipv6_address(text: &str) -> Result<String, String> {
    if text.contains('/') {
        return Err(format!("Unexpected '/' in {}", py_repr(text)));
    }
    let (address, scope) = match text.split_once('%') {
        None => (text, None),
        Some((_, scope)) if scope.is_empty() || scope.contains('%') => {
            return Err(format!("Invalid IPv6 address: \"{}\"", py_repr(text)));
        }
        Some((address, scope)) => (address, Some(scope)),
    };
    let value = ipv6_int(address)?;
    let mut out = ipv6_str(value);
    if let Some(scope) = scope {
        out.push('%');
        out.push_str(scope);
    }
    Ok(out)
}

fn ipv6_int(text: &str) -> Result<u128, String> {
    if text.is_empty() {
        return Err("Address cannot be empty".into());
    }
    let mut parts: Vec<String> = text.split(':').map(str::to_string).collect();
    if parts.len() < 3 {
        return Err(format!("At least 3 parts expected in {}", py_repr(text)));
    }
    if let Some(last) = parts.pop_if(|last| last.contains('.')) {
        let v4 = ipv4_int(&last).map_err(|err| format!("{err} in {}", py_repr(text)))?;
        parts.push(format!("{:x}", (v4 >> 16) & 0xffff));
        parts.push(format!("{:x}", v4 & 0xffff));
    }
    if parts.len() > 9 {
        return Err(format!("At most 8 colons permitted in {}", py_repr(text)));
    }
    let mut skip_index = None;
    for (index, part) in parts.iter().enumerate().take(parts.len() - 1).skip(1) {
        if part.is_empty() {
            if skip_index.is_some() {
                return Err(format!("At most one '::' permitted in {}", py_repr(text)));
            }
            skip_index = Some(index);
        }
    }
    let (parts_hi, parts_lo, skipped) = match skip_index {
        Some(index) => {
            let mut hi = index;
            let mut lo = parts.len() - index - 1;
            if parts[0].is_empty() {
                hi -= 1;
                if hi > 0 {
                    return Err(format!("Leading ':' only permitted as part of '::' in {}", py_repr(text)));
                }
            }
            if parts[parts.len() - 1].is_empty() {
                lo -= 1;
                if lo > 0 {
                    return Err(format!("Trailing ':' only permitted as part of '::' in {}", py_repr(text)));
                }
            }
            if hi + lo >= 8 {
                return Err(format!("Expected at most 7 other parts with '::' in {}", py_repr(text)));
            }
            (hi, lo, 8 - (hi + lo))
        }
        None => {
            if parts.len() != 8 {
                return Err(format!("Exactly 8 parts expected without '::' in {}", py_repr(text)));
            }
            if parts[0].is_empty() {
                return Err(format!("Leading ':' only permitted as part of '::' in {}", py_repr(text)));
            }
            if parts[7].is_empty() {
                return Err(format!("Trailing ':' only permitted as part of '::' in {}", py_repr(text)));
            }
            (8, 0, 0)
        }
    };
    let mut value: u128 = 0;
    let parse = |part: &str| parse_hextet(part).map_err(|err| format!("{err} in {}", py_repr(text)));
    for part in &parts[..parts_hi] {
        value = (value << 16) | u128::from(parse(part)?);
    }
    value = value.checked_shl(16 * skipped as u32).unwrap_or(0);
    for part in &parts[parts.len() - parts_lo..] {
        value = (value << 16) | u128::from(parse(part)?);
    }
    Ok(value)
}

fn parse_hextet(part: &str) -> Result<u16, String> {
    if !part.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("Only hex digits permitted in {}", py_repr(part)));
    }
    if part.chars().count() > 4 {
        return Err(format!("At most 4 characters permitted in {}", py_repr(part)));
    }
    u16::from_str_radix(part, 16).map_err(|_| format!("invalid literal for int() with base 16: {}", py_repr(part)))
}

fn ipv6_str(value: u128) -> String {
    let hextets: Vec<String> = (0..8).rev().map(|i| format!("{:x}", (value >> (16 * i)) & 0xffff)).collect();
    let (mut best_start, mut best_len, mut start, mut len) = (None, 0, None, 0);
    for (index, hextet) in hextets.iter().enumerate() {
        if hextet == "0" {
            len += 1;
            if start.is_none() {
                start = Some(index);
            }
            if len > best_len {
                best_len = len;
                best_start = start;
            }
        } else {
            len = 0;
            start = None;
        }
    }
    let mut parts = hextets;
    if best_len > 1 {
        let begin = best_start.expect("a run was found");
        let end = begin + best_len;
        if end == parts.len() {
            parts.push(String::new());
        }
        parts.splice(begin..end, [String::new()]);
        if begin == 0 {
            parts.insert(0, String::new());
        }
    }
    parts.join(":")
}

/// `str(ipaddress.ip_address(text))`, or Python's `ValueError` text.
pub fn ip_address(text: &str) -> Result<String, String> {
    ipv4_address(text)
        .or_else(|_| ipv6_address(text))
        .map_err(|_| format!("{} does not appear to be an IPv4 or IPv6 address", py_repr(text)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises_like_python() {
        assert_eq!(ip_address("2001:DB8:0:0:0:0:0:1").unwrap(), "2001:db8::1");
        assert_eq!(ip_address("::ffff:1.2.3.4").unwrap(), "::ffff:102:304");
        assert_eq!(ip_address("0:0:0:0:0:0:0:0").unwrap(), "::");
        assert_eq!(ip_address("1:0:0:2:0:0:0:3").unwrap(), "1:0:0:2::3");
        assert_eq!(ip_address("1:0:0:2:0:0:3:4").unwrap(), "1::2:0:0:3:4");
        assert_eq!(ip_address("fe80::1%eth0").unwrap(), "fe80::1%eth0");
        assert_eq!(ipv4_address("01.1.1.1").unwrap_err(), "Leading zeros are not permitted in '01' in '01.1.1.1'");
        assert_eq!(ipv6_address("1.1.1.1").unwrap_err(), "At least 3 parts expected in '1.1.1.1'");
    }
}
