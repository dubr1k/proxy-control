//! The TrustTunnel deep link: `tt://?` + base64url (no padding) of a TLV payload
//! (`panel/trusttunnel_link.py`).
//!
//! The format is the vendor's (TrustTunnel `DEEP_LINK.md`, version 2): every field is a tag, a
//! length and a value, tag and length as QUIC variable-length integers (RFC 9000 §16). The decoder
//! reads up to version 2, skips tags it does not know and refuses a higher version. The encoder
//! writes version 1: version 2 only adds `subscription_url`, which the panel never writes, and the
//! stable official client (TrustTunnelClient 1.1.11) refuses a version-2 link outright.

use base64::Engine as _;
use serde_json::{json, Map, Value};

use crate::util::b64decode_lenient;

pub const SCHEME: &str = "tt://?";
/// The highest version the decoder reads.
pub const VERSION: u64 = 2;
/// What the encoder writes: every official client reads it.
pub const WRITE_VERSION: u64 = 1;
pub const UPSTREAM_HTTP2: u64 = 1;
pub const UPSTREAM_HTTP3: u64 = 2;

pub const TAG_VERSION: u64 = 0x00;
pub const TAG_HOSTNAME: u64 = 0x01;
pub const TAG_ADDRESSES: u64 = 0x02;
pub const TAG_CUSTOM_SNI: u64 = 0x03;
pub const TAG_HAS_IPV6: u64 = 0x04;
pub const TAG_USERNAME: u64 = 0x05;
pub const TAG_PASSWORD: u64 = 0x06;
pub const TAG_SKIP_VERIFICATION: u64 = 0x07;
pub const TAG_CERTIFICATE: u64 = 0x08;
pub const TAG_UPSTREAM_PROTOCOL: u64 = 0x09;
pub const TAG_ANTI_DPI: u64 = 0x0A;
pub const TAG_CLIENT_RANDOM_PREFIX: u64 = 0x0B;
pub const TAG_NAME: u64 = 0x0C;
pub const TAG_DNS_UPSTREAMS: u64 = 0x0D;
pub const TAG_SUBSCRIPTION_URL: u64 = 0x0E;
pub const TAG_CLIENT_RANDOM_AUTH_KEY: u64 = 0x0F;

/// The vendor asks implementations to handle at least 8 KiB; no secret is this large.
pub const MAX_LINK: usize = 16384;

/// A link that is not a valid TrustTunnel deep link. Messages never carry a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeepLinkError(pub String);

impl std::fmt::Display for DeepLinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DeepLinkError {}

fn error(message: &str) -> DeepLinkError {
    DeepLinkError(message.to_string())
}

/// A QUIC variable-length integer (1, 2, 4 or 8 bytes).
pub fn encode_varint(value: i128) -> Result<Vec<u8>, DeepLinkError> {
    if !(0..1 << 62).contains(&value) {
        return Err(error("varint out of range"));
    }
    let value = value as u64;
    Ok(if value < 1 << 6 {
        vec![value as u8]
    } else if value < 1 << 14 {
        ((0x4000 | value) as u16).to_be_bytes().to_vec()
    } else if value < 1 << 30 {
        ((0x8000_0000 | value) as u32).to_be_bytes().to_vec()
    } else {
        (0xC000_0000_0000_0000 | value).to_be_bytes().to_vec()
    })
}

/// The integer at `offset` and the offset after it.
pub fn decode_varint(data: &[u8], offset: usize) -> Result<(u64, usize), DeepLinkError> {
    let first = *data.get(offset).ok_or_else(|| error("truncated payload"))?;
    let size = 1usize << (first >> 6);
    if offset + size > data.len() {
        return Err(error("truncated payload"));
    }
    let value = data[offset + 1..offset + size]
        .iter()
        .fold(u64::from(first & 0x3F), |value, byte| (value << 8) | u64::from(*byte));
    Ok((value, offset + size))
}

fn field(out: &mut Vec<u8>, tag: u64, value: &[u8]) {
    out.extend(encode_varint(i128::from(tag)).expect("tags are small"));
    out.extend(encode_varint(value.len() as i128).expect("a value fits a varint"));
    out.extend_from_slice(value);
}

/// What one access's link carries (`encode_deeplink(...)` keyword arguments).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeepLinkSpec {
    pub hostname: String,
    pub addresses: Vec<String>,
    pub username: String,
    pub password: String,
    /// The concatenated DER chain; omitted (or empty) when the system store trusts the endpoint.
    pub certificate_der: Option<Vec<u8>>,
    pub upstream_protocol: u64,
    pub name: Option<String>,
    pub skip_verification: bool,
}

impl DeepLinkSpec {
    /// The required fields, with the defaults (HTTP/2, no certificate, no name, verification on).
    pub fn new(hostname: &str, addresses: Vec<String>, username: &str, password: &str) -> Self {
        Self {
            hostname: hostname.to_string(),
            addresses,
            username: username.to_string(),
            password: password.to_string(),
            certificate_der: None,
            upstream_protocol: UPSTREAM_HTTP2,
            name: None,
            skip_verification: false,
        }
    }
}

/// The `tt://?` link for one access. Fields at their default (`has_ipv6`, `anti_dpi`,
/// `skip_verification` false) are left out, as the specification allows.
pub fn encode_deeplink(spec: &DeepLinkSpec) -> Result<String, DeepLinkError> {
    if spec.hostname.is_empty() || spec.addresses.is_empty() || spec.username.is_empty() || spec.password.is_empty() {
        return Err(error("hostname, addresses, username and password are required"));
    }
    if !matches!(spec.upstream_protocol, UPSTREAM_HTTP2 | UPSTREAM_HTTP3) {
        return Err(error("unknown upstream protocol"));
    }
    let mut payload = Vec::new();
    field(&mut payload, TAG_VERSION, &encode_varint(i128::from(WRITE_VERSION))?);
    field(&mut payload, TAG_HOSTNAME, spec.hostname.as_bytes());
    for address in &spec.addresses {
        field(&mut payload, TAG_ADDRESSES, address.as_bytes());
    }
    field(&mut payload, TAG_USERNAME, spec.username.as_bytes());
    field(&mut payload, TAG_PASSWORD, spec.password.as_bytes());
    if spec.skip_verification {
        field(&mut payload, TAG_SKIP_VERIFICATION, b"\x01");
    }
    if let Some(certificate) = spec.certificate_der.as_deref().filter(|der| !der.is_empty()) {
        field(&mut payload, TAG_CERTIFICATE, certificate);
    }
    field(&mut payload, TAG_UPSTREAM_PROTOCOL, &encode_varint(i128::from(spec.upstream_protocol))?);
    if let Some(name) = spec.name.as_deref().filter(|name| !name.is_empty()) {
        field(&mut payload, TAG_NAME, name.as_bytes());
    }
    Ok(format!("{SCHEME}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload)))
}

/// Every field of a link (absent ones at their specified default).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeepLink {
    pub version: u64,
    pub hostname: Option<String>,
    pub addresses: Vec<String>,
    pub custom_sni: Option<String>,
    pub has_ipv6: bool,
    pub username: Option<String>,
    pub password: Option<String>,
    pub skip_verification: bool,
    pub certificate: Option<Vec<u8>>,
    pub upstream_protocol: u64,
    pub anti_dpi: bool,
    pub client_random_prefix: Option<String>,
    pub name: Option<String>,
    pub dns_upstreams: Vec<String>,
    pub subscription_url: Option<String>,
    pub client_random_auth_key: Option<String>,
}

impl DeepLink {
    /// The dict Python returns (only the fields present; the certificate as standard base64).
    pub fn to_value(&self) -> Value {
        let mut out = Map::new();
        out.insert("version".into(), json!(self.version));
        out.insert("addresses".into(), json!(self.addresses));
        out.insert("has_ipv6".into(), json!(self.has_ipv6));
        out.insert("skip_verification".into(), json!(self.skip_verification));
        out.insert("anti_dpi".into(), json!(self.anti_dpi));
        out.insert("upstream_protocol".into(), json!(self.upstream_protocol));
        out.insert("dns_upstreams".into(), json!(self.dns_upstreams));
        let texts = [
            ("hostname", &self.hostname),
            ("custom_sni", &self.custom_sni),
            ("username", &self.username),
            ("password", &self.password),
            ("client_random_prefix", &self.client_random_prefix),
            ("name", &self.name),
            ("subscription_url", &self.subscription_url),
            ("client_random_auth_key", &self.client_random_auth_key),
        ];
        for (key, value) in texts {
            if let Some(value) = value {
                out.insert(key.into(), json!(value));
            }
        }
        if let Some(certificate) = &self.certificate {
            out.insert("certificate".into(), json!(base64::engine::general_purpose::STANDARD.encode(certificate)));
        }
        Value::Object(out)
    }
}

fn text(value: &[u8]) -> Result<String, DeepLinkError> {
    String::from_utf8(value.to_vec()).map_err(|_| error("a text field is not UTF-8"))
}

fn string_list(value: &[u8]) -> Result<Vec<String>, DeepLinkError> {
    let (mut items, mut offset) = (Vec::new(), 0);
    while offset < value.len() {
        let (length, next) = decode_varint(value, offset)?;
        offset = next;
        let end = usize::try_from(length).ok().and_then(|length| offset.checked_add(length));
        let end = end.filter(|end| *end <= value.len()).ok_or_else(|| error("truncated payload"))?;
        items.push(text(&value[offset..end])?);
        offset = end;
    }
    Ok(items)
}

/// Every field of a link; unknown tags are skipped. A malformed, too-new or incomplete link is a
/// [`DeepLinkError`].
pub fn decode_deeplink(link: &str) -> Result<DeepLink, DeepLinkError> {
    if !link.starts_with(SCHEME) || link.chars().count() > MAX_LINK {
        return Err(error("not a tt:// deep link"));
    }
    let body = &link[SCHEME.len()..];
    if !body.is_ascii() {
        return Err(error("the payload is not base64url"));
    }
    let padding = "=".repeat((4 - body.len() % 4) % 4);
    let translated: Vec<u8> = format!("{body}{padding}")
        .bytes()
        .map(|byte| match byte {
            b'-' => b'+',
            b'_' => b'/',
            other => other,
        })
        .collect();
    let data = b64decode_lenient(&translated).map_err(|_| error("the payload is not base64url"))?;
    let mut fields = DeepLink {
        version: 0,
        hostname: None,
        addresses: Vec::new(),
        custom_sni: None,
        has_ipv6: true,
        username: None,
        password: None,
        skip_verification: false,
        certificate: None,
        upstream_protocol: UPSTREAM_HTTP2,
        anti_dpi: false,
        client_random_prefix: None,
        name: None,
        dns_upstreams: Vec::new(),
        subscription_url: None,
        client_random_auth_key: None,
    };
    let mut offset = 0;
    while offset < data.len() {
        let (tag, next) = decode_varint(&data, offset)?;
        let (length, next) = decode_varint(&data, next)?;
        let end = usize::try_from(length).ok().and_then(|length| next.checked_add(length));
        let end = end.filter(|end| *end <= data.len()).ok_or_else(|| error("truncated payload"))?;
        let value = &data[next..end];
        offset = end;
        match tag {
            TAG_VERSION => fields.version = decode_varint(value, 0)?.0,
            TAG_ADDRESSES => fields.addresses.push(text(value)?),
            TAG_HAS_IPV6 => fields.has_ipv6 = value == b"\x01",
            TAG_SKIP_VERIFICATION => fields.skip_verification = value == b"\x01",
            TAG_ANTI_DPI => fields.anti_dpi = value == b"\x01",
            TAG_CERTIFICATE => fields.certificate = Some(value.to_vec()),
            TAG_UPSTREAM_PROTOCOL => fields.upstream_protocol = decode_varint(value, 0)?.0,
            TAG_DNS_UPSTREAMS => fields.dns_upstreams = string_list(value)?,
            TAG_HOSTNAME => fields.hostname = Some(text(value)?),
            TAG_CUSTOM_SNI => fields.custom_sni = Some(text(value)?),
            TAG_USERNAME => fields.username = Some(text(value)?),
            TAG_PASSWORD => fields.password = Some(text(value)?),
            TAG_CLIENT_RANDOM_PREFIX => fields.client_random_prefix = Some(text(value)?),
            TAG_NAME => fields.name = Some(text(value)?),
            TAG_SUBSCRIPTION_URL => fields.subscription_url = Some(text(value)?),
            TAG_CLIENT_RANDOM_AUTH_KEY => fields.client_random_auth_key = Some(text(value)?),
            _ => {}
        }
    }
    if fields.version > VERSION {
        return Err(error("the deep link is newer than this decoder"));
    }
    if fields.subscription_url.is_none() {
        for (name, value) in
            [("hostname", &fields.hostname), ("username", &fields.username), ("password", &fields.password)]
        {
            if value.is_none() {
                return Err(DeepLinkError(format!("the deep link has no {name}")));
            }
        }
        if fields.addresses.is_empty() {
            return Err(error("the deep link has no addresses"));
        }
    }
    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_follow_rfc_9000() {
        assert_eq!(encode_varint(0).unwrap(), b"\x00");
        assert_eq!(encode_varint(63).unwrap(), b"\x3f");
        assert_eq!(encode_varint(64).unwrap(), b"\x40\x40");
        assert_eq!(encode_varint(300).unwrap(), b"\x41\x2c");
        assert_eq!(encode_varint(16383).unwrap(), b"\x7f\xff");
        assert_eq!(encode_varint(16384).unwrap(), b"\x80\x00\x40\x00");
        assert_eq!(encode_varint(1 << 30).unwrap(), b"\xc0\x00\x00\x00\x40\x00\x00\x00");
        for value in [0, 1, 63, 64, 300, 16383, 16384, (1 << 30) - 1, 1 << 30, (1 << 62) - 1] {
            let encoded = encode_varint(value).unwrap();
            assert_eq!(decode_varint(&encoded, 0).unwrap(), (value as u64, encoded.len()));
        }
        assert!(encode_varint(1 << 62).is_err());
        assert!(decode_varint(b"\x41", 0).is_err());
    }

    #[test]
    fn a_known_vector_derived_by_hand() {
        let link = encode_deeplink(&DeepLinkSpec::new("h", vec!["a:1".into()], "u", "p")).unwrap();
        assert_eq!(link, "tt://?AAEBAQFoAgNhOjEFAXUGAXAJAQE");
        let decoded = decode_deeplink(&link).unwrap();
        assert_eq!(
            (decoded.version, decoded.hostname.as_deref(), decoded.addresses.clone()),
            (1, Some("h"), vec!["a:1".into()])
        );
        assert_eq!(
            (decoded.username.as_deref(), decoded.password.as_deref(), decoded.upstream_protocol),
            (Some("u"), Some("p"), 1)
        );
        assert!(decoded.has_ipv6 && !decoded.skip_verification && decoded.certificate.is_none());
    }

    #[test]
    fn a_long_value_uses_a_two_byte_length() {
        let link = encode_deeplink(&DeepLinkSpec::new("h", vec!["a:1".into()], "u", &"p".repeat(300))).unwrap();
        assert_eq!(decode_deeplink(&link).unwrap().password.unwrap(), "p".repeat(300));
    }

    #[test]
    fn a_subscription_only_link_needs_no_static_fields() {
        let mut payload = Vec::new();
        field(&mut payload, TAG_VERSION, &encode_varint(2).unwrap());
        field(&mut payload, TAG_SUBSCRIPTION_URL, b"https://sub.example/x");
        let link = format!("{SCHEME}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload));
        assert_eq!(decode_deeplink(&link).unwrap().subscription_url.as_deref(), Some("https://sub.example/x"));
    }
}
