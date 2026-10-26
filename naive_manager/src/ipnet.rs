//! `str(ipaddress.ip_network(text, strict=False))` of Python 3.13: the ACL subject
//! normalisation (netmask and hostmask forms, IPv6 scope ids, IPv4-mapped rendering).

fn parse_octet(text: &str) -> Option<u32> {
    if text.is_empty() || text.len() > 3 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if text != "0" && text.starts_with('0') {
        return None;
    }
    text.parse::<u32>().ok().filter(|v| *v <= 255)
}

fn parse_v4(text: &str) -> Option<u32> {
    let octets: Vec<&str> = text.split('.').collect();
    if octets.len() != 4 {
        return None;
    }
    octets.iter().try_fold(0u32, |acc, octet| Some((acc << 8) | parse_octet(octet)?))
}

fn parse_hextet(text: &str) -> Option<u128> {
    if text.is_empty() || text.len() > 4 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u128::from_str_radix(text, 16).ok()
}

fn parse_v6(text: &str) -> Option<u128> {
    if text.is_empty() || text.chars().count() > 45 {
        return None;
    }
    let mut parts: Vec<String> = text.split(':').map(String::from).collect();
    if parts.len() < 3 {
        return None;
    }
    if parts.last().is_some_and(|last| last.contains('.')) {
        let v4 = parse_v4(&parts.pop()?)?;
        parts.push(format!("{:x}", (v4 >> 16) & 0xFFFF));
        parts.push(format!("{:x}", v4 & 0xFFFF));
    }
    if parts.len() > 9 {
        return None;
    }
    let mut skip = None;
    for (index, part) in parts.iter().enumerate().take(parts.len() - 1).skip(1) {
        if part.is_empty() {
            if skip.is_some() {
                return None;
            }
            skip = Some(index);
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
    let mut value: u128 = 0;
    for part in &parts[..hi] {
        value = (value << 16) | parse_hextet(part)?;
    }
    value = value.checked_shl(16 * skipped).unwrap_or(0);
    for part in &parts[parts.len() - lo..] {
        value = (value << 16) | parse_hextet(part)?;
    }
    Some(value)
}

fn v4_text(value: u32) -> String {
    format!("{}.{}.{}.{}", value >> 24, (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF)
}

fn v6_text(value: u128) -> String {
    if value >> 32 == 0xFFFF {
        return format!("::ffff:{}", v4_text(value as u32));
    }
    let hextets: Vec<u128> = (0..8).map(|i| (value >> (16 * (7 - i))) & 0xFFFF).collect();
    // The longest run of zero hextets longer than one, the first such run on a tie.
    let (mut best_start, mut best_len) = (None, 0);
    let (mut start, mut len) = (None, 0);
    for (index, hextet) in hextets.iter().enumerate() {
        if *hextet == 0 {
            if start.is_none() {
                start = Some(index);
            }
            len += 1;
            if len > best_len {
                best_len = len;
                best_start = start;
            }
        } else {
            start = None;
            len = 0;
        }
    }
    let texts: Vec<String> = hextets.iter().map(|h| format!("{h:x}")).collect();
    match best_start {
        Some(first) if best_len > 1 => {
            let head = texts[..first].join(":");
            let tail = texts[first + best_len..].join(":");
            format!("{head}::{tail}")
        }
        _ => texts.join(":"),
    }
}

fn prefix_digits(text: &str, max: u32) -> Option<u32> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<u32>().ok().filter(|p| *p <= max)
}

fn prefix_of_mask(mask: u32) -> Option<u32> {
    let ones = mask.leading_ones();
    (mask.checked_shl(ones).unwrap_or(0) == 0).then_some(ones)
}

fn v4_network(address: &str, mask: Option<&str>) -> Option<String> {
    let value = parse_v4(address)?;
    let prefix = match mask {
        None => 32,
        Some(mask) => match prefix_digits(mask, 32) {
            Some(prefix) => prefix,
            None if mask.bytes().all(|b| b.is_ascii_digit()) && !mask.is_empty() => return None,
            None => {
                let mask = parse_v4(mask)?;
                prefix_of_mask(mask).or_else(|| prefix_of_mask(!mask))?
            }
        },
    };
    let netmask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    Some(format!("{}/{prefix}", v4_text(value & netmask)))
}

fn v6_network(address: &str, mask: Option<&str>) -> Option<String> {
    let (address, scope) = match address.split_once('%') {
        None => (address, None),
        Some((_, scope)) if scope.is_empty() || scope.contains('%') => return None,
        Some((address, scope)) => (address, Some(scope)),
    };
    let value = parse_v6(address)?;
    let prefix = match mask {
        None => 128,
        Some(mask) => prefix_digits(mask, 128)?,
    };
    let netmask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
    let masked = value & netmask;
    // Masking host bits builds a new address, which drops the scope id.
    let scope = if masked == value { scope } else { None };
    let text = v6_text(masked);
    Some(match scope {
        Some(scope) => format!("{text}%{scope}/{prefix}"),
        None => format!("{text}/{prefix}"),
    })
}

/// `str(ipaddress.ip_network(text, strict=False))`, or `None` for a `ValueError`.
pub fn ip_network(text: &str) -> Option<String> {
    let parts: Vec<&str> = text.split('/').collect();
    if parts.len() > 2 {
        return None;
    }
    let mask = parts.get(1).copied();
    v4_network(parts[0], mask).or_else(|| v6_network(parts[0], mask))
}
