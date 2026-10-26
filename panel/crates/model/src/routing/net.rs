//! `ipaddress.IPv4Address(text)` with CPython 3.13's messages and `str(ipaddress.ip_network(text,
//! strict=False))`, on top of `panel_core::pytext::ip_address` (these belong next to it in
//! `panel-core` eventually).

use panel_core::pytext::{self, IpAddress, PyValueError};

/// `ipaddress.IPv4Address(text)`: the address, or `AddressValueError`'s message.
pub fn ipv4_address(text: &str) -> Result<u32, PyValueError> {
    let fail = |message: String| Err(PyValueError(message));
    if text.contains('/') {
        return fail(format!("Unexpected '/' in {}", pytext::repr(text)));
    }
    if text.is_empty() {
        return fail("Address cannot be empty".into());
    }
    let octets: Vec<&str> = text.split('.').collect();
    if octets.len() != 4 {
        return fail(format!("Expected 4 octets in {}", pytext::repr(text)));
    }
    let mut value = 0u32;
    for octet in octets {
        match parse_octet(octet) {
            Ok(byte) => value = value << 8 | byte,
            Err(message) => return fail(format!("{message} in {}", pytext::repr(text))),
        }
    }
    Ok(value)
}

fn parse_octet(octet: &str) -> Result<u32, String> {
    if octet.is_empty() {
        return Err("Empty octet not permitted".into());
    }
    if !octet.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("Only decimal digits permitted in {}", pytext::repr(octet)));
    }
    if octet.len() > 3 {
        return Err(format!("At most 3 characters permitted in {}", pytext::repr(octet)));
    }
    if octet != "0" && octet.starts_with('0') {
        return Err(format!("Leading zeros are not permitted in {}", pytext::repr(octet)));
    }
    let value: u32 = octet.parse().expect("one to three ASCII digits");
    if value > 255 {
        return Err(format!("Octet {value} (> 255) not permitted"));
    }
    Ok(value)
}

/// `str(ipaddress.ip_network(text, strict=False))`: host bits cleared, a bare address as its /32
/// or /128, an IPv4 netmask or hostmask accepted in place of a prefix length. `None` where Python
/// raises `ValueError`.
pub fn ip_network(text: &str) -> Option<String> {
    let parts: Vec<&str> = text.split('/').collect();
    if parts.len() > 2 {
        return None;
    }
    let address = pytext::ip_address(parts[0]).ok()?;
    match address {
        IpAddress::V4(value) => {
            let prefix = match parts.get(1) {
                None => 32,
                Some(mask) => v4_prefix(mask)?,
            };
            let netmask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            Some(format!("{}/{prefix}", IpAddress::V4(value & netmask)))
        }
        IpAddress::V6(value, scope) => {
            let prefix = match parts.get(1) {
                None => 128,
                Some(mask) => prefix_length(mask, 128)?,
            };
            let netmask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
            // Python rebuilds the address (dropping its scope) only when host bits were set.
            let network = if value & netmask == value {
                IpAddress::V6(value, scope)
            } else {
                IpAddress::V6(value & netmask, None)
            };
            Some(format!("{network}/{prefix}"))
        }
    }
}

/// `_prefix_from_prefix_string`: ASCII digits only, at most `max`.
fn prefix_length(text: &str, max: u32) -> Option<u32> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let value: u128 = text.parse().ok().or_else(|| text.trim_start_matches('0').is_empty().then_some(0))?;
    (value <= u128::from(max)).then_some(value as u32)
}

/// An IPv4 prefix: a length, or a dotted netmask or hostmask.
fn v4_prefix(text: &str) -> Option<u32> {
    if let Some(prefix) = prefix_length(text, 32) {
        return Some(prefix);
    }
    if !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None; // a length out of range is not retried as a netmask
    }
    let mask = ipv4_address(text).ok()?;
    contiguous_prefix(mask).or_else(|| contiguous_prefix(!mask))
}

/// The prefix length of `mask` if it is ones followed by zeros.
fn contiguous_prefix(mask: u32) -> Option<u32> {
    let ones = mask.leading_ones();
    (mask.checked_shl(ones).unwrap_or(0) == 0).then_some(ones)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn networks_print_like_python() {
        assert_eq!(ip_network("10.0.0.5/8").as_deref(), Some("10.0.0.0/8"));
        assert_eq!(ip_network("10.0.0.0/255.0.0.0").as_deref(), Some("10.0.0.0/8"));
        assert_eq!(ip_network("10.0.0.0/0.0.0.255").as_deref(), Some("10.0.0.0/24"));
        assert_eq!(ip_network("1.2.3.4/0.0.0.0").as_deref(), Some("0.0.0.0/0"));
        assert_eq!(ip_network("10.0.0.0/255.0.255.0"), None);
        assert_eq!(ip_network("fe80::1%eth0/64").as_deref(), Some("fe80::/64"));
        assert_eq!(ip_network("fe80::%eth0/64").as_deref(), Some("fe80::%eth0/64"));
        assert_eq!(ip_network("1.2.3.4/64"), None);
    }

    #[test]
    fn ipv4_messages_are_pythons() {
        assert_eq!(ipv4_address("1.2.3").unwrap_err().0, "Expected 4 octets in '1.2.3'");
        assert_eq!(ipv4_address("999.1.1.1").unwrap_err().0, "Octet 999 (> 255) not permitted in '999.1.1.1'");
        assert_eq!(ipv4_address("10.8.0.2"), Ok(0x0a08_0002));
    }
}
