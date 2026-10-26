//! The two `ipaddress` questions the compiler asks: does a network overlap one of the private
//! ranges, and is an address inside a network. Networks come from the policy, already in the
//! canonical `address/prefix` form `normalise_cidr` stored.

use panel_core::pytext::{ip_address, IpAddress};

/// `ipaddress.ip_network(text)`: the network address (as 128 bits, IPv4 in the low 32), its
/// version and prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Network {
    pub v6: bool,
    pub address: u128,
    pub prefix: u32,
}

impl Network {
    pub fn parse(text: &str) -> Option<Self> {
        let (address, prefix) = match text.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (text, None),
        };
        let (v6, value) = match ip_address(address).ok()? {
            IpAddress::V4(value) => (false, u128::from(value)),
            IpAddress::V6(value, _) => (true, value),
        };
        let bits = if v6 { 128 } else { 32 };
        let prefix = match prefix {
            None => bits,
            Some(text) if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) => text.parse().ok()?,
            Some(_) => return None,
        };
        (prefix <= bits).then_some(Self { v6, address: value, prefix })
    }

    fn bits(&self) -> u32 {
        if self.v6 {
            128
        } else {
            32
        }
    }

    fn mask(&self, prefix: u32) -> u128 {
        let bits = self.bits();
        let all = if bits == 128 { u128::MAX } else { (1u128 << bits) - 1 };
        if prefix == 0 {
            0
        } else {
            all & (all << (bits - prefix))
        }
    }

    /// `self.overlaps(other)` for two networks of one version.
    pub fn overlaps(&self, other: &Network) -> bool {
        if self.v6 != other.v6 {
            return false;
        }
        let mask = self.mask(self.prefix.min(other.prefix));
        self.address & mask == other.address & mask
    }

    /// `address in self` (Python compares the bits only, a scope does not matter).
    pub fn contains(&self, address: &IpAddress) -> bool {
        let (v6, value) = match address {
            IpAddress::V4(value) => (false, u128::from(*value)),
            IpAddress::V6(value, _) => (true, *value),
        };
        let mask = self.mask(self.prefix);
        v6 == self.v6 && value & mask == self.address & mask
    }
}

/// `PRIVATE_NETWORKS` of the compiler: what a `direct`/`egress` rule may never open.
pub const PRIVATE_NETWORKS: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
];

/// Whether `cidr` overlaps a private range of its version.
pub fn is_private_network(cidr: &str) -> bool {
    let Some(network) = Network::parse(cidr) else {
        return false;
    };
    PRIVATE_NETWORKS.iter().filter_map(|text| Network::parse(text)).any(|private| network.overlaps(&private))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_ranges_overlap_like_python() {
        for cidr in ["127.0.0.1/32", "10.1.2.0/24", "192.168.0.0/16", "169.254.1.1/32", "::1/128", "fd00::/8", "0.0.0.0/0"]
        {
            assert!(is_private_network(cidr), "{cidr}");
        }
        for cidr in ["203.0.113.0/24", "1.1.1.0/24", "2001:db8::/32", "11.0.0.0/8"] {
            assert!(!is_private_network(cidr), "{cidr}");
        }
    }

    #[test]
    fn membership_ignores_the_scope() {
        let network = Network::parse("203.0.113.0/24").unwrap();
        assert!(network.contains(&ip_address("203.0.113.9").unwrap()));
        assert!(!network.contains(&ip_address("203.0.114.9").unwrap()));
        assert!(!network.contains(&ip_address("::1").unwrap()));
        let v6 = Network::parse("fe80::/10").unwrap();
        assert!(v6.contains(&ip_address("fe80::1%eth0").unwrap()));
    }
}
