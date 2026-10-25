//! The leaf certificate the endpoint serves: its DER, fingerprint and a trust heuristic.
//!
//! Only the few fields the heuristic needs are read from the DER (issuer, validity, subject), so
//! the manager carries no X.509 library.

use std::path::Path;

use base64::Engine;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    pub der: Vec<u8>,
    pub fingerprint: String,
    /// True for a certificate that is not self-signed and not expired; a self-signed leaf must
    /// be pinned by the client, so its DER is exposed.
    pub trusted: bool,
}

const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const END: &str = "-----END CERTIFICATE-----";

/// Fingerprint, trust heuristic and DER of the leaf; `None` when unreadable. `now` is the wall
/// clock in seconds since the epoch.
pub fn inspect_certificate(path: &Path, now: f64) -> Option<CertInfo> {
    let pem = std::fs::read_to_string(path).ok()?;
    // fullchain.pem carries the leaf and its intermediates: the leaf is the first block only.
    let start = pem.find(BEGIN)?;
    let end = start + pem[start..].find(END)?;
    let body: String = pem[start + BEGIN.len()..end].chars().filter(|c| !c.is_whitespace()).collect();
    let der = base64::engine::general_purpose::STANDARD.decode(body).ok()?;
    let trusted = match leaf_fields(&der) {
        Some(fields) => fields.not_after >= now && fields.issuer != fields.subject,
        None => false,
    };
    let fingerprint = hex(&Sha256::digest(&der));
    Some(CertInfo { der, fingerprint, trusted })
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct LeafFields<'a> {
    issuer: &'a [u8],
    subject: &'a [u8],
    not_after: f64,
}

/// One DER element: (tag, the whole element, its content, what follows).
type Element<'a> = (u8, &'a [u8], &'a [u8], &'a [u8]);

fn element(data: &[u8]) -> Option<Element<'_>> {
    let tag = *data.first()?;
    let first = *data.get(1)? as usize;
    let (length, header) = if first < 0x80 {
        (first, 2)
    } else {
        let count = first & 0x7f;
        if count == 0 || count > 4 {
            return None;
        }
        let mut length = 0usize;
        for i in 0..count {
            length = (length << 8) | *data.get(2 + i)? as usize;
        }
        (length, 2 + count)
    };
    let total = header.checked_add(length)?;
    if data.len() < total {
        return None;
    }
    Some((tag, &data[..total], &data[header..total], &data[total..]))
}

fn leaf_fields(der: &[u8]) -> Option<LeafFields<'_>> {
    let (0x30, _, certificate, _) = element(der)? else { return None };
    let (0x30, _, tbs, _) = element(certificate)? else { return None };
    let mut rest = tbs;
    let (tag, _, _, after) = element(rest)?;
    if tag == 0xa0 {
        rest = after; // explicit version
    }
    let (0x02, _, _, rest) = element(rest)? else { return None }; // serial
    let (0x30, _, _, rest) = element(rest)? else { return None }; // signature algorithm
    let (0x30, issuer, _, rest) = element(rest)? else { return None };
    let (0x30, _, validity, rest) = element(rest)? else { return None };
    let (0x30, subject, _, _) = element(rest)? else { return None };
    let (_, _, _, after_not_before) = element(validity)?;
    let (time_tag, _, not_after, _) = element(after_not_before)?;
    let not_after = parse_time(time_tag, not_after)?;
    Some(LeafFields { issuer, subject, not_after })
}

/// UTCTime (`YYMMDDHHMMSSZ`) or GeneralizedTime (`YYYYMMDDHHMMSSZ`) to seconds since the epoch.
fn parse_time(tag: u8, raw: &[u8]) -> Option<f64> {
    let text = std::str::from_utf8(raw).ok()?.strip_suffix('Z')?;
    let (year, rest) = match tag {
        0x17 if text.len() == 12 => {
            let yy: i64 = text[..2].parse().ok()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &text[2..])
        }
        0x18 if text.len() == 14 => (text[..4].parse().ok()?, &text[4..]),
        _ => return None,
    };
    if !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let field = |i: usize| rest[i..i + 2].parse::<i64>().ok();
    let (month, day, hour, minute, second) = (field(0)?, field(2)?, field(4)?, field(6)?, field(8)?);
    let days = days_from_civil(year, month, day);
    Some((days * 86_400 + hour * 3600 + minute * 60 + second) as f64)
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn openssl(dir: &Path, args: &[&str]) {
        let status = Command::new("openssl").args(args).current_dir(dir).output().expect("openssl is installed");
        assert!(status.status.success(), "{}", String::from_utf8_lossy(&status.stderr));
    }

    fn now() -> f64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64()
    }

    #[test]
    fn dates_convert_like_the_calendar() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 2, 29), 11_016);
        assert_eq!(parse_time(0x17, b"491231235959Z"), Some(2_524_607_999.0));
        assert_eq!(parse_time(0x17, b"500101000000Z"), Some(-631_152_000.0));
        assert_eq!(days_from_civil(2026, 10, 25), 20_751);
        assert_eq!(parse_time(0x18, b"20261025000102Z"), Some(20_751.0 * 86_400.0 + 62.0));
        assert_eq!(parse_time(0x17, b"2610250000Z"), None);
    }

    #[test]
    fn self_signed_certificate_is_untrusted_with_a_fingerprint() {
        let dir = crate::state::tests::tempdir("cert-self");
        openssl(
            &dir,
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                "key.pem",
                "-out",
                "cert.pem",
                "-days",
                "30",
                "-subj",
                "/CN=gate.example.com",
            ],
        );
        let found = inspect_certificate(&dir.join("cert.pem"), now()).unwrap();
        assert!(!found.trusted && found.fingerprint.len() == 64);
        assert!(inspect_certificate(&dir.join("missing.pem"), now()).is_none());
    }

    #[test]
    fn a_fullchain_file_is_read_by_its_leaf_and_counts_as_trusted() {
        let dir = crate::state::tests::tempdir("cert-chain");
        openssl(
            &dir,
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                "ca.key",
                "-out",
                "ca.pem",
                "-days",
                "30",
                "-subj",
                "/CN=Test Intermediate",
            ],
        );
        openssl(
            &dir,
            &[
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                "leaf.key",
                "-out",
                "leaf.csr",
                "-subj",
                "/CN=gate.example.com",
            ],
        );
        openssl(
            &dir,
            &[
                "x509",
                "-req",
                "-in",
                "leaf.csr",
                "-CA",
                "ca.pem",
                "-CAkey",
                "ca.key",
                "-CAcreateserial",
                "-out",
                "leaf.pem",
                "-days",
                "30",
            ],
        );
        openssl(&dir, &["x509", "-in", "leaf.pem", "-outform", "DER", "-out", "leaf.der"]);
        let chain = std::fs::read_to_string(dir.join("leaf.pem")).unwrap()
            + &std::fs::read_to_string(dir.join("ca.pem")).unwrap();
        std::fs::write(dir.join("fullchain.pem"), chain).unwrap();
        let found =
            inspect_certificate(&dir.join("fullchain.pem"), now()).expect("a two-certificate chain is readable");
        assert!(found.trusted);
        assert_eq!(found.der, std::fs::read(dir.join("leaf.der")).unwrap());
        // The same leaf after its notAfter is no longer trusted.
        assert!(!inspect_certificate(&dir.join("fullchain.pem"), now() + 40.0 * 86_400.0).unwrap().trusted);
    }
}
