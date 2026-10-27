//! Python 3.13's `ipaddress` as the manager used it: `ip_address(value)` validity (DNS host
//! entries, IPv6 brackets in links) and `str(ip_network(value, strict=False))` (CIDR selectors).

use serde_json::Value;


const V4_BITS: u32 = 32;
const V6_BITS: u32 = 128;

fn ascii_digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
}

/// `IPv4Address(text)`: four decimal octets, no leading zeros, no signs or spaces.
pub fn parse_v4(text: &str) -> Option<u32> {
    if text.is_empty() || text.contains('/') {
        return None;
    }
    let octets: Vec<&str> = text.split('.').collect();
    if octets.len() != 4 {
        return None;
    }
    let mut value = 0u32;
    for octet in octets {
        if !ascii_digits(octet) || octet.len() > 3 || (octet != "0" && octet.starts_with('0')) {
            return None;
        }
        let byte: u32 = octet.parse().ok()?;
        if byte > 255 {
            return None;
        }
        value = (value << 8) | byte;
    }
    Some(value)
}

fn parse_hextet(text: &str) -> Option<u128> {
    if text.is_empty() || text.len() > 4 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u128::from_str_radix(text, 16).ok()
}

/// `IPv6Address._ip_int_from_string`: `::` once, an IPv4 tail, at most eight hextets.
fn parse_v6_bare(text: &str) -> Option<u128> {
    if text.is_empty() {
        return None;
    }
    let mut parts: Vec<String> = text.split(':').map(str::to_string).collect();
    if parts.len() < 3 {
        return None;
    }
    if parts.last().is_some_and(|last| last.contains('.')) {
        let v4 = parse_v4(&parts.pop()?)?;
        parts.push(format!("{:x}", (v4 >> 16) & 0xffff));
        parts.push(format!("{:x}", v4 & 0xffff));
    }
    if parts.len() > 9 {
        return None;
    }
    let mut skip = None;
    for (i, part) in parts.iter().enumerate().take(parts.len() - 1).skip(1) {
        if part.is_empty() {
            if skip.is_some() {
                return None;
            }
            skip = Some(i);
        }
    }
    let (hi, lo, skipped) = match skip {
        Some(index) => {
            let mut hi = index;
            let mut lo = parts.len() - index - 1;
            if parts[0].is_empty() {
                hi -= 1;
                if hi != 0 {
                    return None;
                }
            }
            if parts[parts.len() - 1].is_empty() {
                lo -= 1;
                if lo != 0 {
                    return None;
                }
            }
            let skipped = 8i32 - (hi + lo) as i32;
            if skipped < 1 {
                return None;
            }
            (hi, lo, skipped as u32)
        }
        None => {
            if parts.len() != 8 || parts[0].is_empty() || parts[7].is_empty() {
                return None;
            }
            (parts.len(), 0, 0)
        }
    };
    let mut value = 0u128;
    for part in &parts[..hi] {
        value = (value << 16) | parse_hextet(part)?;
    }
    // `::` alone skips all eight hextets: nothing above them to shift.
    value = value.checked_shl(16 * skipped).unwrap_or(0);
    for part in &parts[parts.len() - lo..] {
        value = (value << 16) | parse_hextet(part)?;
    }
    Some(value)
}

/// `IPv6Address(text)`: the address and its scope id (`%eth0`), if any.
pub fn parse_v6(text: &str) -> Option<(u128, Option<String>)> {
    if text.contains('/') {
        return None;
    }
    let (address, scope) = match text.split_once('%') {
        Some((address, scope)) => {
            if scope.is_empty() || scope.contains('%') {
                return None;
            }
            (address, Some(scope.to_string()))
        }
        None => (text, None),
    };
    Some((parse_v6_bare(address)?, scope))
}

/// 4 or 6 for a valid `ip_address(text)`.
pub fn address_version(text: &str) -> Option<u8> {
    if parse_v4(text).is_some() {
        Some(4)
    } else if parse_v6(text).is_some() {
        Some(6)
    } else {
        None
    }
}

/// `ipaddress.ip_address(value)` succeeds: a string address, or an integer in range (a bool
/// is an int to Python).
pub fn is_address(value: &Value) -> bool {
    match value {
        Value::String(text) => address_version(text).is_some(),
        Value::Bool(_) => true,
        Value::Number(_) => pc_common::pyvalue::strict_int(value).is_some_and(|n| n >= 0),
        _ => false,
    }
}

/// `ipaddress.ip_network(value, strict=False)` succeeds.
pub fn is_network(value: &Value) -> bool {
    match value {
        Value::String(text) => network_str(text).is_some(),
        Value::Bool(_) => true,
        Value::Number(_) => pc_common::pyvalue::strict_int(value).is_some_and(|n| n >= 0),
        _ => false,
    }
}

fn prefix_string(text: &str, bits: u32) -> Option<u32> {
    if !ascii_digits(text) {
        return None;
    }
    let trimmed = text.trim_start_matches('0');
    let value: u32 = if trimmed.is_empty() { 0 } else { trimmed.parse().ok()? };
    (value <= bits).then_some(value)
}

/// A netmask (`/1*0*/`) or hostmask (`/0*1*/`) in dotted form, as a prefix length.
fn prefix_from_v4_mask(text: &str) -> Option<u32> {
    let mask = parse_v4(text)?;
    let from_int = |value: u32| -> Option<u32> {
        let trailing = if value == 0 { V4_BITS } else { value.trailing_zeros() };
        let prefix = V4_BITS - trailing;
        let leading = if trailing == V4_BITS { 0 } else { value >> trailing };
        let all_ones = if prefix == 0 { 0 } else { u32::MAX >> (V4_BITS - prefix) };
        (leading == all_ones).then_some(prefix)
    };
    from_int(mask).or_else(|| from_int(!mask))
}

fn v4_text(value: u32) -> String {
    let b = value.to_be_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

/// `str(IPv6Address)` in Python 3.13: the IPv4-mapped range prints its dotted tail, every
/// other address compresses the longest run of two or more zero hextets.
pub fn v6_text(value: u128, scope: Option<&str>) -> String {
    let body = if value >> 32 == 0xffff {
        format!("::ffff:{}", v4_text(value as u32))
    } else {
        let hextets: Vec<String> = (0..8).map(|i| format!("{:x}", (value >> (112 - 16 * i)) & 0xffff)).collect();
        let (mut best_start, mut best_len, mut start, mut len) = (0usize, 0usize, 0usize, 0usize);
        for (i, hextet) in hextets.iter().enumerate() {
            if hextet == "0" {
                if len == 0 {
                    start = i;
                }
                len += 1;
                if len > best_len {
                    best_len = len;
                    best_start = start;
                }
            } else {
                len = 0;
            }
        }
        if best_len > 1 {
            let head = hextets[..best_start].join(":");
            let tail = hextets[best_start + best_len..].join(":");
            format!("{head}::{tail}")
        } else {
            hextets.join(":")
        }
    };
    match scope {
        Some(scope) => format!("{body}%{scope}"),
        None => body,
    }
}

/// `str(ipaddress.ip_network(text, strict=False))`, or `None` where Python raises.
pub fn network_str(text: &str) -> Option<String> {
    let parts: Vec<&str> = text.split('/').collect();
    if parts.len() > 2 {
        return None;
    }
    let mask = parts.get(1).copied();
    // IPv4Network first, then IPv6Network, as ip_network tries them.
    if let Some(address) = parse_v4(parts[0]) {
        let prefix = match mask {
            None => Some(V4_BITS),
            Some(mask) => prefix_string(mask, V4_BITS).or_else(|| prefix_from_v4_mask(mask)),
        };
        if let Some(prefix) = prefix {
            let netmask = if prefix == 0 { 0 } else { u32::MAX << (V4_BITS - prefix) };
            return Some(format!("{}/{prefix}", v4_text(address & netmask)));
        }
    }
    let (address, scope) = parse_v6(parts[0])?;
    let prefix = match mask {
        None => V6_BITS,
        Some(mask) => prefix_string(mask, V6_BITS)?,
    };
    let netmask = if prefix == 0 { 0 } else { u128::MAX << (V6_BITS - prefix) };
    // With host bits set the network address is rebuilt from the integer and loses its scope.
    if address & netmask != address {
        return Some(format!("{}/{prefix}", v6_text(address & netmask, None)));
    }
    Some(format!("{}/{prefix}", v6_text(address, scope.as_deref())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hextet_compression_follows_python() {
        assert_eq!(v6_text(1, None), "::1");
        assert_eq!(v6_text(0, None), "::");
        assert_eq!(v6_text(0x0001_0000_0000_0001_0000_0000_0000_0001, None), "1:0:0:1::1");
        assert_eq!(v6_text(0x0001_0002_0003_0004_0005_0006_0007_0000, None), "1:2:3:4:5:6:7:0");
        assert_eq!(network_str("2001:db8::1%eth0").as_deref(), Some("2001:db8::1%eth0/128"));
    }
}
