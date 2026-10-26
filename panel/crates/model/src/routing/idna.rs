//! `text.encode("idna")` of CPython 3.13 (`encodings.idna`, IDNA 2003): labels split on the four
//! dots, ASCII labels kept as they are, other labels through nameprep (RFC 3491 with CPython's
//! `stringprep` tables, `tables.rs`) and Punycode with the `xn--` prefix.
//!
//! One approximation: nameprep's final NFKC uses `panel_core`'s current Unicode data instead of
//! Unicode 3.2, which can differ only for characters assigned after 3.2 that have compatibility
//! decompositions (see DIFFERENCES.md).

use panel_core::pytext;

use super::tables;

fn in_table(table: &[(u32, u32)], ch: char) -> bool {
    let code = ch as u32;
    table
        .binary_search_by(|&(start, end)| {
            if end < code {
                std::cmp::Ordering::Less
            } else if start > code {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// `str.isdigit()` for one character.
pub(crate) fn is_digit(ch: char) -> bool {
    pytext::decimal(ch).is_some() || in_table(tables::DIGIT_NOT_DECIMAL, ch)
}

/// Why a name cannot be encoded (Python raises `UnicodeError`; the panel only needs the fact).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdnaError(pub &'static str);

/// `name.encode("idna").decode("ascii")`.
pub fn encode(name: &str) -> Result<String, IdnaError> {
    if name.is_empty() {
        return Ok(String::new());
    }
    if name.is_ascii() {
        let labels: Vec<&str> = name.split('.').collect();
        if labels[..labels.len() - 1].iter().any(|label| label.is_empty()) {
            return Err(IdnaError("label empty"));
        }
        if labels.iter().any(|label| label.len() >= 64) {
            return Err(IdnaError("label too long"));
        }
        return Ok(name.to_string());
    }
    let mut labels: Vec<&str> = name.split(['.', '\u{3002}', '\u{ff0e}', '\u{ff61}']).collect();
    let trailing_dot = labels.len() > 1 && labels.last().is_some_and(|label| label.is_empty());
    if trailing_dot {
        labels.pop();
    }
    let mut out = String::new();
    for label in labels {
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&to_ascii(label)?);
    }
    if trailing_dot {
        out.push('.');
    }
    Ok(out)
}

fn check_length(label: &str) -> Result<String, IdnaError> {
    match label.len() {
        0 => Err(IdnaError("label empty")),
        1..=63 => Ok(label.to_string()),
        _ => Err(IdnaError("label too long")),
    }
}

/// RFC 3490 ToASCII with `UseSTD3ASCIIRules` off and unassigned code points allowed.
fn to_ascii(label: &str) -> Result<String, IdnaError> {
    if label.is_ascii() {
        return check_length(label);
    }
    let prepared = nameprep(label)?;
    if prepared.is_ascii() {
        return check_length(&prepared);
    }
    if pytext::lower(&prepared).starts_with("xn--") {
        return Err(IdnaError("Label starts with ACE prefix"));
    }
    check_length(&format!("xn--{}", punycode(&prepared)))
}

/// RFC 3491 nameprep: map (B.1 to nothing, B.2 case folding), NFKC, prohibit, check bidi.
fn nameprep(label: &str) -> Result<String, IdnaError> {
    let mut mapped = String::with_capacity(label.len());
    for ch in label.chars() {
        if in_table(tables::B1, ch) {
            continue;
        }
        match tables::B2_EXCEPTIONS.binary_search_by_key(&(ch as u32), |&(code, _)| code) {
            Ok(index) => mapped.push_str(tables::B2_EXCEPTIONS[index].1),
            Err(_) => mapped.extend(ch.to_lowercase()),
        }
    }
    let label = pytext::nfkc(&mapped);
    if label.chars().any(|ch| in_table(tables::PROHIBITED, ch)) {
        return Err(IdnaError("Invalid character"));
    }
    let rand_al: Vec<bool> = label.chars().map(|ch| in_table(tables::RAND_AL, ch)).collect();
    if rand_al.iter().any(|flag| *flag) {
        if label.chars().any(|ch| in_table(tables::BIDI_L, ch)) {
            return Err(IdnaError("Violation of BIDI requirement 2"));
        }
        if !rand_al[0] || !rand_al[rand_al.len() - 1] {
            return Err(IdnaError("Violation of BIDI requirement 3"));
        }
    }
    Ok(label)
}

/// RFC 3492 Punycode encoding (what Python's `"punycode"` codec writes).
fn punycode(input: &str) -> String {
    const BASE: u32 = 36;
    const T_MIN: u32 = 1;
    const T_MAX: u32 = 26;
    const SKEW: u32 = 38;
    const DAMP: u32 = 700;
    let digit =
        |value: u32| -> char { char::from(if value < 26 { b'a' + value as u8 } else { b'0' + (value - 26) as u8 }) };
    let adapt = |mut delta: u32, points: u32, first: bool| -> u32 {
        delta = if first { delta / DAMP } else { delta / 2 };
        delta += delta / points;
        let mut k = 0;
        while delta > ((BASE - T_MIN) * T_MAX) / 2 {
            delta /= BASE - T_MIN;
            k += BASE;
        }
        k + (BASE - T_MIN + 1) * delta / (delta + SKEW)
    };
    let code_points: Vec<u32> = input.chars().map(|ch| ch as u32).collect();
    let mut out: String = input.chars().filter(char::is_ascii).collect();
    let basic = out.len() as u32;
    if basic > 0 {
        out.push('-');
    }
    let mut n: u32 = 0x80;
    let mut delta: u32 = 0;
    let mut bias: u32 = 72;
    let mut handled = basic;
    while (handled as usize) < code_points.len() {
        let m = code_points.iter().copied().filter(|&code| code >= n).min().expect("a non-basic code point is left");
        delta += (m - n) * (handled + 1);
        n = m;
        for &code in &code_points {
            if code < n {
                delta += 1;
            }
            if code == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = if k <= bias {
                        T_MIN
                    } else if k >= bias + T_MAX {
                        T_MAX
                    } else {
                        k - bias
                    };
                    if q < t {
                        break;
                    }
                    out.push(digit(t + (q - t) % (BASE - t)));
                    q = (q - t) / (BASE - t);
                    k += BASE;
                }
                out.push(digit(q));
                bias = adapt(delta, handled + 1, handled == basic);
                delta = 0;
                handled += 1;
            }
        }
        delta += 1;
        n += 1;
    }
    // Python's codec writes the basic code points, then `-` only when there were some (above).
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_names() {
        assert_eq!(encode("пример.рф").unwrap(), "xn--e1afmkfd.xn--p1ai");
        assert_eq!(encode("straße.de").unwrap(), "strasse.de");
        assert_eq!(encode("日本。jp").unwrap(), "xn--wgv71a.jp");
        assert_eq!(encode("bücher").unwrap(), "xn--bcher-kva");
        assert!(encode("\u{5d0}a.com").is_err());
    }
}
