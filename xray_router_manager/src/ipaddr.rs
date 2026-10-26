//! Python 3.13's `ipaddress` where the intent leans on it: `ip_address()` as a test of an address,
//! `ip_network(text, strict=False)` and its `str()` as the normal form of a CIDR. Leading zeros,
//! netmasks and host masks after the slash, scope ids, and the dotted IPv4-mapped form all follow
//! the standard library (golden data in `testdata/intent.json`).

const HEX_DIGITS: &str = "0123456789abcdefABCDEF";

/// `IPv4Address(text)`.
pub fn parse_v4(text: &str) -> Option<u32> {
    if text.is_empty() {
        return None;
    }
    let octets: Vec<&str> = text.split('.').collect();
    if octets.len() != 4 {
        return None;
    }
    let mut value: u32 = 0;
    for octet in octets {
        if octet.is_empty() || !octet.bytes().all(|b| b.is_ascii_digit()) || octet.len() > 3 {
            return None;
        }
        if octet != "0" && octet.starts_with('0') {
            return None;
        }
        let number: u32 = octet.parse().ok()?;
        if number > 255 {
            return None;
        }
        value = (value << 8) | number;
    }
    Some(value)
}

fn parse_hextet(text: &str) -> Option<u128> {
    if !text.chars().all(|c| HEX_DIGITS.contains(c)) || text.len() > 4 || text.is_empty() {
        return None;
    }
    u128::from_str_radix(text, 16).ok()
}

/// `IPv6Address._ip_int_from_string(text)` (no scope id).
fn v6_int(text: &str) -> Option<u128> {
    if text.is_empty() || text.chars().count() > 45 {
        return None;
    }
    let mut parts: Vec<String> = text.split(':').map(str::to_string).collect();
    if parts.len() < 3 {
        return None;
    }
    if parts.last().is_some_and(|last| last.contains('.')) {
        let v4 = parse_v4(&parts.pop().expect("checked above"))?;
        parts.push(format!("{:x}", (v4 >> 16) & 0xffff));
        parts.push(format!("{:x}", v4 & 0xffff));
    }
    if parts.len() > 9 {
        return None;
    }
    let mut skip_index = None;
    for (i, part) in parts.iter().enumerate().take(parts.len() - 1).skip(1) {
        if part.is_empty() {
            if skip_index.is_some() {
                return None;
            }
            skip_index = Some(i);
        }
    }
    let (parts_hi, parts_lo, skipped) = match skip_index {
        Some(skip) => {
            let mut hi = skip;
            let mut lo = parts.len() - skip - 1;
            if parts[0].is_empty() {
                hi -= 1;
                if hi > 0 {
                    return None;
                }
            }
            if parts[parts.len() - 1].is_empty() {
                lo -= 1;
                if lo > 0 {
                    return None;
                }
            }
            let skipped = 8i64 - (hi + lo) as i64;
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
    let mut value: u128 = 0;
    for part in &parts[..parts_hi] {
        value = (value << 16) | parse_hextet(part)?;
    }
    value = value.checked_shl(16 * skipped).unwrap_or(0);
    for part in &parts[parts.len() - parts_lo..] {
        value = (value << 16) | parse_hextet(part)?;
    }
    Some(value)
}

/// `IPv6Address(text)`: the address and its scope id.
pub fn parse_v6(text: &str) -> Option<(u128, Option<String>)> {
    let (address, scope) = match text.split_once('%') {
        None => (text, None),
        Some((_, scope)) if scope.is_empty() || scope.contains('%') => return None,
        Some((address, scope)) => (address, Some(scope.to_string())),
    };
    if address.contains('/') {
        return None;
    }
    Some((v6_int(address)?, scope))
}

pub fn format_v4(value: u32) -> String {
    let [a, b, c, d] = value.to_be_bytes();
    format!("{a}.{b}.{c}.{d}")
}

/// `str(IPv6Address)`: zeros compressed (the first longest run of two or more), the
/// IPv4-mapped range as `::ffff:a.b.c.d`, the scope id appended.
pub fn format_v6(value: u128, scope: Option<&str>) -> String {
    let text = if value >> 32 == 0xffff {
        format!("::ffff:{}", format_v4(value as u32))
    } else {
        let hextets: Vec<String> = (0..8).rev().map(|i| format!("{:x}", (value >> (16 * i)) & 0xffff)).collect();
        let (mut best_start, mut best_len, mut start, mut len) = (0usize, 0usize, None, 0usize);
        for (index, hextet) in hextets.iter().enumerate() {
            if hextet == "0" {
                len += 1;
                let begin = *start.get_or_insert(index);
                if len > best_len {
                    best_len = len;
                    best_start = begin;
                }
            } else {
                len = 0;
                start = None;
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
        Some(scope) => format!("{text}%{scope}"),
        None => text,
    }
}

/// Whether `ipaddress.ip_address(text)` accepts the text.
pub fn is_ip_address(text: &str) -> bool {
    (!text.contains('/') && parse_v4(text).is_some()) || parse_v6(text).is_some()
}

fn prefix_from_string(text: &str, max: u32) -> Option<u32> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let value: u64 = text.parse().ok().or(if text.len() > 19 { Some(u64::MAX) } else { None })?;
    (value <= max as u64).then_some(value as u32)
}

fn prefix_from_v4_int(value: u32) -> Option<u32> {
    let trailing = if value == 0 { 32 } else { value.trailing_zeros() };
    let prefix = 32 - trailing;
    let leading = if trailing == 32 { 0 } else { value >> trailing };
    let all_ones = ((1u64 << prefix) - 1) as u32;
    (leading == all_ones).then_some(prefix)
}

fn v4_netmask(text: &str) -> Option<u32> {
    if let Some(prefix) = prefix_from_string(text, 32) {
        return Some(prefix);
    }
    let value = parse_v4(text)?;
    prefix_from_v4_int(value).or_else(|| prefix_from_v4_int(value ^ u32::MAX))
}

fn mask_v4(prefix: u32) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn mask_v6(prefix: u32) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

/// `str(ipaddress.ip_network(text, strict=False))`, or `None` where it raises.
pub fn network(text: &str) -> Option<String> {
    let parts: Vec<&str> = text.split('/').collect();
    if parts.len() > 2 {
        return None;
    }
    let address = parts[0];
    if let Some(ip) = parse_v4(address) {
        let prefix = match parts.get(1) {
            Some(mask) => v4_netmask(mask),
            None => Some(32),
        };
        if let Some(prefix) = prefix {
            return Some(format!("{}/{prefix}", format_v4(ip & mask_v4(prefix))));
        }
    }
    let (ip, scope) = parse_v6(address)?;
    let prefix = match parts.get(1) {
        Some(mask) => prefix_from_string(mask, 128)?,
        None => 128,
    };
    let masked = ip & mask_v6(prefix);
    // Host bits make a new address: the scope id stays only on an address that was already the
    // network's.
    let scope = if masked == ip { scope } else { None };
    Some(format!("{}/{prefix}", format_v6(masked, scope.as_deref())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn networks_normalise_like_the_standard_library() {
        for (input, output) in [
            ("10.1.2.3/8", Some("10.0.0.0/8")),
            ("10.9.0.0/0.255.255.255", Some("10.0.0.0/8")),
            ("1.2.3.4/024", Some("1.2.3.0/24")),
            ("01.2.3.4", None),
            ("::ffff:0:0/96", Some("::ffff:0.0.0.0/96")),
            ("::1.2.3.4", Some("::102:304/128")),
            ("1:2:3:4:5:6:7::", Some("1:2:3:4:5:6:7:0/128")),
            ("fe80::%eth0/64", Some("fe80::%eth0/64")),
            ("fe80::1%eth0/64", Some("fe80::/64")),
            ("1.2.3.4/255.255.0.255", None),
            ("2001:db8::1/ffff::", None),
        ] {
            assert_eq!(network(input).as_deref(), output, "{input}");
        }
        assert!(is_ip_address("203.0.113.7") && is_ip_address("2001:DB8::1") && !is_ip_address("1.2.3.4/32"));
    }
}
