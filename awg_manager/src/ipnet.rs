//! The part of Python's `ipaddress` the manager uses: IPv4 networks (strict and not), membership,
//! overlap, `subnet_of`, `hosts()`, and "is this an IP address" for the DNS list.

use std::fmt;
use std::net::Ipv6Addr;

/// `IPv4Address(text)`: four decimal octets, no leading zeros, nothing else.
pub fn parse_v4(text: &str) -> Option<u32> {
    let octets: Vec<&str> = text.split('.').collect();
    if octets.len() != 4 {
        return None;
    }
    let mut value = 0u32;
    for octet in octets {
        if octet.is_empty() || octet.len() > 3 || !octet.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if octet != "0" && octet.starts_with('0') {
            return None;
        }
        let byte: u32 = octet.parse().ok()?;
        if byte > 255 {
            return None;
        }
        value = value << 8 | byte;
    }
    Some(value)
}

pub fn format_v4(value: u32) -> String {
    let b = value.to_be_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

/// `IPv6Address(text)`, including a `%scope` suffix.
fn parse_v6(text: &str) -> Option<u128> {
    let (address, scope) = match text.split_once('%') {
        Some((address, scope)) => (address, Some(scope)),
        None => (text, None),
    };
    if scope.is_some_and(|scope| scope.is_empty() || scope.contains('%')) {
        return None;
    }
    address.parse::<Ipv6Addr>().ok().map(u128::from)
}

/// `ipaddress.ip_address(text)` succeeds.
pub fn is_ip_address(text: &str) -> bool {
    parse_v4(text).is_some() || parse_v6(text).is_some()
}

fn prefix_digits(text: &str, max: u32) -> Option<u32> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<u32>().ok().filter(|prefix| *prefix <= max)
}

/// A contiguous netmask (`255.255.255.0`) to its prefix length.
fn prefix_from_mask(mask: u32) -> Option<u32> {
    let zeros = if mask == 0 { 32 } else { mask.trailing_zeros() };
    let prefix = 32 - zeros;
    let ones = if zeros == 32 { 0 } else { mask >> zeros };
    let expected = if prefix == 0 { 0 } else { u32::MAX >> (32 - prefix) };
    (ones == expected).then_some(prefix)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Net {
    pub network: u32,
    pub prefix: u32,
}

impl Ipv4Net {
    pub fn mask(&self) -> u32 {
        if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix)
        }
    }

    pub fn broadcast(&self) -> u32 {
        self.network | !self.mask()
    }

    pub fn contains(&self, address: u32) -> bool {
        address & self.mask() == self.network
    }

    pub fn subnet_of(&self, other: &Ipv4Net) -> bool {
        other.network <= self.network && other.broadcast() >= self.broadcast()
    }

    pub fn overlaps(&self, other: &Ipv4Net) -> bool {
        self.contains(other.network)
            || self.contains(other.broadcast())
            || other.contains(self.network)
            || other.contains(self.broadcast())
    }

    /// The first address after the network address (the gateway the manager takes).
    pub fn gateway(&self) -> u32 {
        self.network + 1
    }

    /// `hosts()`: every address but the network and broadcast ones (all of a /31 or /32).
    pub fn hosts(&self) -> impl Iterator<Item = u32> {
        let (first, last) =
            if self.prefix >= 31 { (self.network, self.broadcast()) } else { (self.network + 1, self.broadcast() - 1) };
        first..=last
    }
}

impl fmt::Display for Ipv4Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", format_v4(self.network), self.prefix)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    V4(Ipv4Net),
    /// A valid IPv6 network; the manager only needs to know it is not IPv4.
    V6,
}

/// `IPv4Network(text, strict)`: `address[/prefix|/netmask|/hostmask]`.
fn parse_v4_network(text: &str, strict: bool) -> Option<Ipv4Net> {
    let parts: Vec<&str> = text.split('/').collect();
    if parts.len() > 2 {
        return None;
    }
    let address = parse_v4(parts[0])?;
    let prefix = match parts.get(1) {
        None => 32,
        Some(raw) => match prefix_digits(raw, 32) {
            Some(prefix) => prefix,
            None => {
                let mask = parse_v4(raw)?;
                prefix_from_mask(mask).or_else(|| prefix_from_mask(!mask))?
            }
        },
    };
    let net = Ipv4Net { network: address, prefix };
    let masked = address & net.mask();
    if strict && masked != address {
        return None;
    }
    Some(Ipv4Net { network: masked, prefix })
}

/// `IPv6Network(text, strict)`: only a prefix length, as Python takes it.
fn parse_v6_network(text: &str, strict: bool) -> bool {
    let parts: Vec<&str> = text.split('/').collect();
    if parts.len() > 2 {
        return false;
    }
    let Some(address) = parse_v6(parts[0]) else { return false };
    let prefix = match parts.get(1) {
        None => 128,
        Some(raw) => match prefix_digits(raw, 128) {
            Some(prefix) => prefix,
            None => return false,
        },
    };
    let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
    !strict || address & mask == address
}

/// `ipaddress.ip_network(text, strict=strict)`.
pub fn ip_network(text: &str, strict: bool) -> Option<Network> {
    if let Some(net) = parse_v4_network(text, strict) {
        return Some(Network::V4(net));
    }
    parse_v6_network(text, strict).then_some(Network::V6)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(text: &str) -> Ipv4Net {
        match ip_network(text, true) {
            Some(Network::V4(net)) => net,
            other => panic!("{text}: {other:?}"),
        }
    }

    #[test]
    fn networks_parse_like_ipaddress() {
        assert_eq!(v4("10.66.15.0/24").to_string(), "10.66.15.0/24");
        assert_eq!(v4("10.66.15.0/255.255.255.0").prefix, 24);
        assert_eq!(v4("10.66.15.0/0.0.0.255").prefix, 24);
        assert_eq!(v4("10.0.0.1").prefix, 32);
        assert_eq!(ip_network("10.66.15.5/24", true), None);
        assert_eq!(
            ip_network("10.66.15.5/24", false),
            Some(Network::V4(Ipv4Net { network: parse_v4("10.66.15.0").unwrap(), prefix: 24 }))
        );
        assert_eq!(ip_network("fd00::/64", true), Some(Network::V6));
        for bad in ["", "10.0.0.0/33", "10.0.0.0/255.0.255.0", "010.0.0.0/8", "1.2.3/8", "10.0.0.0/8/8", "x"] {
            assert_eq!(ip_network(bad, true), None, "{bad}");
        }
    }

    #[test]
    fn membership_overlap_and_hosts() {
        let net = v4("10.66.20.0/28");
        assert!(net.contains(parse_v4("10.66.20.15").unwrap()) && !net.contains(parse_v4("10.66.20.16").unwrap()));
        assert!(net.subnet_of(&v4("10.0.0.0/8")) && !net.subnet_of(&v4("192.168.0.0/16")));
        assert!(net.overlaps(&v4("10.66.20.8/29")) && !net.overlaps(&v4("10.66.20.16/28")));
        let hosts: Vec<String> = net.hosts().map(format_v4).collect();
        assert_eq!((hosts.len(), hosts[0].as_str(), hosts[13].as_str()), (14, "10.66.20.1", "10.66.20.14"));
        assert_eq!(format_v4(net.gateway()), "10.66.20.1");
    }

    #[test]
    fn addresses_v4_and_v6() {
        for good in ["1.1.1.1", "::1", "2606:4700::1111", "fe80::1%eth0", "::ffff:1.2.3.4"] {
            assert!(is_ip_address(good), "{good}");
        }
        for bad in ["not-an-ip", "1.1.1", "01.1.1.1", "1.1.1.256", "fe80::1%", ""] {
            assert!(!is_ip_address(bad), "{bad}");
        }
    }
}
