//! `ipaddress.ip_address` of CPython 3.13: its parser (strict dotted quads, `%scope` on IPv6), its
//! text form and its special-purpose address tables. `std::net` classifies addresses differently
//! (and some of its predicates are unstable), so the panel's "is this a public address" rule for
//! linked panels uses this port.

use std::fmt;

use super::PyValueError;

/// An address as `ipaddress.ip_address(text)` returns it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IpAddress {
    V4(u32),
    /// The 128-bit address and the optional `%scope` (kept verbatim, as Python does).
    V6(u128, Option<String>),
}

/// `ipaddress.ip_address(text)`: an IPv4 address if `text` parses as one, else an IPv6 address.
pub fn ip_address(text: &str) -> Result<IpAddress, PyValueError> {
    if let Some(value) = parse_v4(text) {
        return Ok(IpAddress::V4(value));
    }
    if let Some((value, scope)) = parse_v6(text) {
        return Ok(IpAddress::V6(value, scope));
    }
    Err(PyValueError(format!("{} does not appear to be an IPv4 or IPv6 address", super::repr(text))))
}

fn parse_octet(text: &str) -> Option<u32> {
    if text.is_empty() || text.len() > 3 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if text != "0" && text.starts_with('0') {
        return None;
    }
    let value: u32 = text.parse().ok()?;
    (value <= 255).then_some(value)
}

fn parse_v4(text: &str) -> Option<u32> {
    if text.is_empty() || text.contains('/') {
        return None;
    }
    let octets: Vec<&str> = text.split('.').collect();
    if octets.len() != 4 {
        return None;
    }
    let mut value = 0u32;
    for octet in octets {
        value = value << 8 | parse_octet(octet)?;
    }
    Some(value)
}

fn parse_hextet(text: &str) -> Option<u128> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_hexdigit()) || text.len() > 4 {
        return None;
    }
    u128::from_str_radix(text, 16).ok()
}

fn parse_v6(text: &str) -> Option<(u128, Option<String>)> {
    if text.contains('/') {
        return None;
    }
    let (address, scope) = match text.split_once('%') {
        None => (text, None),
        Some((_, scope)) if scope.is_empty() || scope.contains('%') => return None,
        Some((address, scope)) => (address, Some(scope.to_string())),
    };
    if address.is_empty() || super::len(address) > 45 {
        return None;
    }
    const HEXTETS: usize = 8;
    // `split(':', maxsplit=9)`: at most ten parts, the last one keeping any further colons.
    let mut parts: Vec<String> = address.splitn(HEXTETS + 2, ':').map(str::to_string).collect();
    if parts.len() < 3 {
        return None;
    }
    if parts.last().is_some_and(|last| last.contains('.')) {
        let v4 = parse_v4(&parts.pop().expect("checked above"))?;
        parts.push(format!("{:x}", v4 >> 16 & 0xFFFF));
        parts.push(format!("{:x}", v4 & 0xFFFF));
    }
    if parts.len() > HEXTETS + 1 {
        return None;
    }
    let mut skip_index = None;
    for (index, part) in parts.iter().enumerate().take(parts.len() - 1).skip(1) {
        if part.is_empty() {
            if skip_index.is_some() {
                return None;
            }
            skip_index = Some(index);
        }
    }
    let (parts_hi, parts_lo, parts_skipped) = if let Some(skip) = skip_index {
        let mut hi = skip;
        let mut lo = parts.len() - skip - 1;
        if parts[0].is_empty() {
            hi -= 1;
            if hi != 0 {
                return None;
            }
        }
        if parts.last().is_some_and(String::is_empty) {
            lo -= 1;
            if lo != 0 {
                return None;
            }
        }
        let skipped = HEXTETS as isize - (hi + lo) as isize;
        if skipped < 1 {
            return None;
        }
        (hi, lo, skipped as usize)
    } else {
        if parts.len() != HEXTETS || parts[0].is_empty() || parts.last().is_some_and(String::is_empty) {
            return None;
        }
        (parts.len(), 0, 0)
    };
    let mut value: u128 = 0;
    for part in &parts[..parts_hi] {
        value = value << 16 | parse_hextet(part)?;
    }
    // `::` alone skips all eight hextets: a 128-bit shift, which Python's ints take in stride.
    value = value.checked_shl(16 * parts_skipped as u32).unwrap_or(0);
    for part in &parts[parts.len() - parts_lo..] {
        value = value << 16 | parse_hextet(part)?;
    }
    Some((value, scope))
}

fn v4_in(address: u32, network: u32, prefix: u32) -> bool {
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    address & mask == network
}

fn v6_in(address: u128, network: u128, prefix: u32) -> bool {
    let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
    address & mask == network
}

const fn v4(a: u8, b: u8, c: u8, d: u8) -> u32 {
    (a as u32) << 24 | (b as u32) << 16 | (c as u32) << 8 | d as u32
}

/// `_IPv4Constants._private_networks` (CPython 3.13).
const V4_PRIVATE: &[(u32, u32)] = &[
    (v4(0, 0, 0, 0), 8),
    (v4(10, 0, 0, 0), 8),
    (v4(127, 0, 0, 0), 8),
    (v4(169, 254, 0, 0), 16),
    (v4(172, 16, 0, 0), 12),
    (v4(192, 0, 0, 0), 24),
    (v4(192, 0, 0, 170), 31),
    (v4(192, 0, 2, 0), 24),
    (v4(192, 168, 0, 0), 16),
    (v4(198, 18, 0, 0), 15),
    (v4(198, 51, 100, 0), 24),
    (v4(203, 0, 113, 0), 24),
    (v4(240, 0, 0, 0), 4),
    (v4(255, 255, 255, 255), 32),
];

/// `_IPv4Constants._private_networks_exceptions`.
const V4_PRIVATE_EXCEPTIONS: &[(u32, u32)] = &[(v4(192, 0, 0, 9), 32), (v4(192, 0, 0, 10), 32)];

/// `_IPv6Constants._private_networks` (CPython 3.13, RFC 9637's `3fff::/20` included).
const V6_PRIVATE: &[(u128, u32)] = &[
    (0x1, 128),
    (0x0, 128),
    (0xffff_0000_0000, 96),
    (0x0064_ff9b_0001 << 80, 48),
    (0x0100 << 112, 64),
    (0x2001 << 112, 23),
    (0x2001_0db8 << 96, 32),
    (0x2002 << 112, 16),
    (0x3fff << 112, 20),
    (0xfc00 << 112, 7),
    (0xfe80 << 112, 10),
];

/// `_IPv6Constants._private_networks_exceptions`.
const V6_PRIVATE_EXCEPTIONS: &[(u128, u32)] = &[
    ((0x2001_0001 << 96) | 1, 128),
    ((0x2001_0001 << 96) | 2, 128),
    (0x2001_0003 << 96, 32),
    (0x2001_0004_0112 << 80, 48),
    (0x2001_0020 << 96, 28),
    (0x2001_0030 << 96, 28),
];

/// `_IPv6Constants._reserved_networks`.
const V6_RESERVED: &[(u128, u32)] = &[
    (0x0, 8),
    (0x0100 << 112, 8),
    (0x0200 << 112, 7),
    (0x0400 << 112, 6),
    (0x0800 << 112, 5),
    (0x1000 << 112, 4),
    (0x4000 << 112, 3),
    (0x6000 << 112, 3),
    (0x8000 << 112, 3),
    (0xA000 << 112, 3),
    (0xC000 << 112, 3),
    (0xE000 << 112, 4),
    (0xF000 << 112, 5),
    (0xF800 << 112, 6),
    (0xFE00 << 112, 9),
];

fn v4_is_private(address: u32) -> bool {
    V4_PRIVATE.iter().any(|&(network, prefix)| v4_in(address, network, prefix))
        && !V4_PRIVATE_EXCEPTIONS.iter().any(|&(network, prefix)| v4_in(address, network, prefix))
}

fn v4_is_global(address: u32) -> bool {
    !v4_in(address, v4(100, 64, 0, 0), 10) && !v4_is_private(address)
}

impl From<std::net::IpAddr> for IpAddress {
    /// A resolver's answer, to classify with Python's tables (no scope).
    fn from(address: std::net::IpAddr) -> Self {
        match address {
            std::net::IpAddr::V4(v4) => IpAddress::V4(u32::from(v4)),
            std::net::IpAddr::V6(v6) => IpAddress::V6(u128::from(v6), None),
        }
    }
}

impl IpAddress {
    /// The address without its scope, for sockets.
    pub fn to_std(&self) -> std::net::IpAddr {
        match self {
            IpAddress::V4(value) => std::net::IpAddr::V4((*value).into()),
            IpAddress::V6(value, _) => std::net::IpAddr::V6((*value).into()),
        }
    }

    /// `address.version`: 4 or 6.
    pub fn version(&self) -> u8 {
        match self {
            IpAddress::V4(_) => 4,
            IpAddress::V6(..) => 6,
        }
    }

    /// `address.ipv4_mapped` for an IPv6 address in `::ffff:0:0/96`.
    pub fn ipv4_mapped(&self) -> Option<u32> {
        match self {
            IpAddress::V6(value, _) if value >> 32 == 0xFFFF => Some(*value as u32),
            _ => None,
        }
    }

    fn v4_view(&self) -> Option<u32> {
        match self {
            IpAddress::V4(value) => Some(*value),
            IpAddress::V6(..) => self.ipv4_mapped(),
        }
    }

    fn v6_value(&self) -> u128 {
        match self {
            IpAddress::V6(value, _) => *value,
            IpAddress::V4(_) => unreachable!("only called on IPv6 without a mapped IPv4"),
        }
    }

    /// `address.is_private` — in IANA's "not globally reachable" tables (`100.64.0.0/10` is
    /// neither private nor global).
    pub fn is_private(&self) -> bool {
        if let Some(address) = self.v4_view() {
            return v4_is_private(address);
        }
        let value = self.v6_value();
        V6_PRIVATE.iter().any(|&(network, prefix)| v6_in(value, network, prefix))
            && !V6_PRIVATE_EXCEPTIONS.iter().any(|&(network, prefix)| v6_in(value, network, prefix))
    }

    /// `address.is_global` — the panel's rule for an address a linked panel may be reached at.
    pub fn is_global(&self) -> bool {
        match self {
            IpAddress::V4(value) => v4_is_global(*value),
            IpAddress::V6(..) => match self.ipv4_mapped() {
                Some(address) => v4_is_global(address),
                None => !self.is_private(),
            },
        }
    }

    /// `address.is_multicast`.
    pub fn is_multicast(&self) -> bool {
        match self.v4_view() {
            Some(address) => v4_in(address, v4(224, 0, 0, 0), 4),
            None => v6_in(self.v6_value(), 0xff00 << 112, 8),
        }
    }

    /// `address.is_loopback`.
    pub fn is_loopback(&self) -> bool {
        match self.v4_view() {
            Some(address) => v4_in(address, v4(127, 0, 0, 0), 8),
            None => self.v6_value() == 1,
        }
    }

    /// `address.is_link_local`.
    pub fn is_link_local(&self) -> bool {
        match self.v4_view() {
            Some(address) => v4_in(address, v4(169, 254, 0, 0), 16),
            None => v6_in(self.v6_value(), 0xfe80 << 112, 10),
        }
    }

    /// `address.is_unspecified`.
    pub fn is_unspecified(&self) -> bool {
        match self.v4_view() {
            Some(address) => address == 0,
            None => self.v6_value() == 0,
        }
    }

    /// `address.is_reserved`.
    pub fn is_reserved(&self) -> bool {
        match self.v4_view() {
            Some(address) => v4_in(address, v4(240, 0, 0, 0), 4),
            None => V6_RESERVED.iter().any(|&(network, prefix)| v6_in(self.v6_value(), network, prefix)),
        }
    }
}

fn format_v4(value: u32) -> String {
    let [a, b, c, d] = value.to_be_bytes();
    format!("{a}.{b}.{c}.{d}")
}

/// `IPv6Address._string_from_ip_int`: lower-case hextets, the longest run (first on a tie) of two
/// or more zero hextets compressed to `::`.
fn format_v6_hextets(value: u128) -> String {
    let hextets: Vec<String> = (0..8).map(|index| format!("{:x}", (value >> (16 * (7 - index))) & 0xFFFF)).collect();
    let (mut best_start, mut best_len, mut start, mut run) = (0usize, 0usize, 0usize, 0usize);
    for (index, hextet) in hextets.iter().enumerate() {
        if hextet == "0" {
            if run == 0 {
                start = index;
            }
            run += 1;
            if run > best_len {
                best_len = run;
                best_start = start;
            }
        } else {
            run = 0;
        }
    }
    if best_len < 2 {
        return hextets.join(":");
    }
    let head = hextets[..best_start].join(":");
    let tail = hextets[best_start + best_len..].join(":");
    format!("{head}::{tail}")
}

impl fmt::Display for IpAddress {
    /// `str(address)`: dotted quad; compressed IPv6, with an IPv4-mapped address's low 32 bits as a
    /// dotted quad (`::ffff:1.2.3.4`) and the `%scope` appended.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpAddress::V4(value) => f.write_str(&format_v4(*value)),
            IpAddress::V6(value, scope) => {
                let text = match self.ipv4_mapped() {
                    Some(v4) => format!("{}:{}", format_v6_hextets(value >> 32), format_v4(v4)),
                    None => format_v6_hextets(*value),
                };
                f.write_str(&text)?;
                if let Some(scope) = scope {
                    write!(f, "%{scope}")?;
                }
                Ok(())
            }
        }
    }
}
