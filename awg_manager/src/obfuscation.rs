//! Per-version AmneziaWG obfuscation parameters: generation, validation, UAPI/client forms.
//!
//! Values are maps of STRINGS keyed with the client-config key names (Jc, Jmin, ..., H1..H4,
//! I1..I5, HeaderProtectionKey, ContentPaddingAddition). They are generated once at the first
//! bootstrap of a version, persisted, and never regenerated.

use indexmap::IndexMap;
use serde_json::Value;

use crate::keys::{b64, hexkey, unb64};

pub type Params = IndexMap<String, String>;

pub const UINT32: u64 = 4_294_967_295;
/// HeaderCipherNonceSize in amneziawg-go.
pub const MIN_HEADER_PROTECTION_PADDING: u64 = 12;
const COMMON: [&str; 9] = ["Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"];
const I_KEYS: [&str; 5] = ["I1", "I2", "I3", "I4", "I5"];
pub const VERSIONS: [&str; 3] = ["1.5", "2.0", "3.1"];

/// The parameters are invalid for the protocol version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObfuscationError(pub String);

impl std::fmt::Display for ObfuscationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ObfuscationError {}

fn err<T>(message: impl Into<String>) -> Result<T, ObfuscationError> {
    Err(ObfuscationError(message.into()))
}

fn extra_keys(version: &str) -> &'static [&'static str] {
    match version {
        "2.0" => &["S3", "S4"],
        "3.1" => &["S3", "S4", "HeaderProtectionKey", "ContentPaddingAddition", "RandomTrailers", "DisableCookies"],
        _ => &[],
    }
}

fn allowed(version: &str, key: &str) -> bool {
    COMMON.contains(&key) || I_KEYS.contains(&key) || extra_keys(version).contains(&key)
}

fn required(version: &str) -> Vec<&'static str> {
    let mut keys = COMMON.to_vec();
    match version {
        "2.0" => keys.extend(["S3", "S4"]),
        "3.1" => keys.extend(["S3", "S4", "HeaderProtectionKey"]),
        _ => {}
    }
    keys
}

// ------------------------------------------------------------------ randomness

/// The random source `generate` draws from: the system's in production, a seeded one in tests.
pub trait Rng: Send {
    /// A uniform integer in `[0, n)`; `n > 0`.
    fn below(&mut self, n: u64) -> u64;
    fn fill(&mut self, out: &mut [u8]);
}

/// `random.SystemRandom`: unbiased draws from the operating system.
pub struct SystemRng;

impl Rng for SystemRng {
    fn below(&mut self, n: u64) -> u64 {
        let limit = u64::MAX - u64::MAX % n;
        loop {
            let mut raw = [0u8; 8];
            self.fill(&mut raw);
            let value = u64::from_le_bytes(raw);
            if value < limit {
                return value % n;
            }
        }
    }

    fn fill(&mut self, out: &mut [u8]) {
        getrandom::fill(out).expect("the system random source is available");
    }
}

/// `random.Random(seed)` for tests: deterministic for a seed (SplitMix64).
#[cfg(test)]
pub struct SeededRng(pub u64);

#[cfg(test)]
impl SeededRng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

#[cfg(test)]
impl Rng for SeededRng {
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn fill(&mut self, out: &mut [u8]) {
        for byte in out {
            *byte = self.next() as u8;
        }
    }
}

/// `rng.randint(lo, hi)`, both ends included.
fn randint(rng: &mut dyn Rng, lo: u64, hi: u64) -> u64 {
    lo + rng.below(hi - lo + 1)
}

/// `rng.shuffle(items)`.
fn shuffle<T>(rng: &mut dyn Rng, items: &mut [T]) {
    for i in (1..items.len()).rev() {
        let j = rng.below(i as u64 + 1) as usize;
        items.swap(i, j);
    }
}

// ------------------------------------------------------------------ validation helpers

fn int(params: &Params, key: &str, lo: u64, hi: u64) -> Result<u64, ObfuscationError> {
    let raw = params.get(key).map(String::as_str).unwrap_or("");
    if raw.is_empty() || raw.len() > 10 || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return err(format!("{key} must be an integer string"));
    }
    let value: u64 = raw.parse().expect("ten ASCII digits fit");
    if !(lo..=hi).contains(&value) {
        return err(format!("{key} must be {lo}-{hi}"));
    }
    Ok(value)
}

fn digits(text: &str) -> bool {
    (1..=10).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_digit())
}

/// `N` or `N-M` (each 1-10 digits), `N <= M <= 2^32-1`.
pub fn parse_range(text: &str, key: &str) -> Result<(u64, u64), ObfuscationError> {
    let (lo, hi) = match text.split_once('-') {
        Some((lo, hi)) if digits(lo) && digits(hi) => (lo, hi),
        None if digits(text) => (text, text),
        _ => return err(format!("{key} must be N or N-M")),
    };
    let (lo, hi): (u64, u64) = (lo.parse().expect("digits"), hi.parse().expect("digits"));
    if lo > hi || hi > UINT32 {
        return err(format!("{key} range is invalid"));
    }
    Ok((lo, hi))
}

/// A CPS string: one or more of `<b 0xHH…>`, `<r N>`, `<rc N>`, `<rd N>`, `<t>`, `<c>`.
pub fn is_cps(text: &str) -> bool {
    let mut rest = text.as_bytes();
    if rest.is_empty() {
        return false;
    }
    while !rest.is_empty() {
        let Some(body) = rest.strip_prefix(b"<") else { return false };
        let after = if let Some(hex) = body.strip_prefix(b"b 0x") {
            let count = hex.iter().take_while(|b| b.is_ascii_hexdigit()).count();
            if count == 0 || count % 2 != 0 {
                return false;
            }
            &hex[count..]
        } else if let Some(number) =
            body.strip_prefix(b"r ").or_else(|| body.strip_prefix(b"rc ")).or_else(|| body.strip_prefix(b"rd "))
        {
            let count = number.iter().take_while(|b| b.is_ascii_digit()).count();
            if !(1..=4).contains(&count) {
                return false;
            }
            &number[count..]
        } else if body.starts_with(b"t") || body.starts_with(b"c") {
            &body[1..]
        } else {
            return false;
        };
        let Some(next) = after.strip_prefix(b">") else { return false };
        rest = next;
    }
    true
}

// ------------------------------------------------------------------ the API

/// `<b 0xC?00000001LL><r LL><b 0x0000><t><r N>`: a QUIC-Initial-looking first packet (long
/// header, v1, random DCID, timestamp, entropy).
pub fn default_i1(rng: &mut dyn Rng) -> String {
    let first = 0xC0 | randint(rng, 0, 3);
    let dcid_len = [8u64, 8, 8, 16, 18, 20][rng.below(6) as usize];
    let tail = randint(rng, 32, 96);
    format!("<b 0x{first:02x}00000001{dcid_len:02x}><r {dcid_len}><b 0x0000><t><r {tail}>")
}

/// Fresh random parameters valid for `version`.
pub fn generate(version: &str, mtu: u64, rng: &mut dyn Rng) -> Result<Params, ObfuscationError> {
    if !VERSIONS.contains(&version) {
        return err(format!("unknown version {version}"));
    }
    let jmin = randint(rng, 8, 24);
    let jmax = (jmin + randint(rng, 40, 120)).min(mtu);
    let mut out = Params::new();
    out.insert("Jc".into(), randint(rng, 4, 8).to_string());
    out.insert("Jmin".into(), jmin.to_string());
    out.insert("Jmax".into(), jmax.to_string());
    let s = if version == "3.1" {
        let mut s: Vec<u64> = (0..4).map(|_| randint(rng, MIN_HEADER_PROTECTION_PADDING, 64)).collect();
        while s[0] + 56 == s[1] {
            s[1] = randint(rng, MIN_HEADER_PROTECTION_PADDING, 64);
        }
        s
    } else {
        let mut s = vec![randint(rng, 15, 150), randint(rng, 15, 150), randint(rng, 8, 64), randint(rng, 8, 64)];
        while s[0] + 56 == s[1] {
            s[1] = randint(rng, 15, 150);
        }
        s
    };
    out.insert("S1".into(), s[0].to_string());
    out.insert("S2".into(), s[1].to_string());
    if version != "1.5" {
        out.insert("S3".into(), s[2].to_string());
        out.insert("S4".into(), s[3].to_string());
    }
    let values: Vec<String> = match version {
        "1.5" => {
            let mut heads: Vec<u64> = Vec::new();
            while heads.len() < 4 {
                let head = randint(rng, 5, UINT32);
                if !heads.contains(&head) {
                    heads.push(head);
                }
            }
            heads.sort_unstable();
            shuffle(rng, &mut heads);
            heads.iter().map(u64::to_string).collect()
        }
        "2.0" => {
            // Four non-overlapping ranges: cut [5, UINT32] into equal quarters, pick one per slot.
            let span = (UINT32 - 5) / 4;
            let mut values: Vec<String> = (0..4)
                .map(|slot| {
                    let base = 5 + slot * span;
                    let lo = base + randint(rng, 0, span / 2 - 1000);
                    let hi = lo + randint(rng, 1000, span / 2 - 1);
                    format!("{lo}-{hi}")
                })
                .collect();
            shuffle(rng, &mut values);
            values
        }
        _ => ["1", "2", "3", "4"].map(String::from).to_vec(),
    };
    for (i, value) in values.into_iter().enumerate() {
        out.insert(format!("H{}", i + 1), value);
    }
    out.insert("I1".into(), default_i1(rng));
    if version == "3.1" {
        let mut key = [0u8; 32];
        rng.fill(&mut key);
        out.insert("HeaderProtectionKey".into(), b64(&key));
        out.insert("ContentPaddingAddition".into(), "0-32".into());
    }
    validate(version, &out, mtu)?;
    Ok(out)
}

/// The parameters stored in the state (a JSON object of strings).
pub fn from_value(value: &Value) -> Result<Params, ObfuscationError> {
    let Some(map) = value.as_object() else { return err("parameters must be a string map") };
    map.iter()
        .map(|(key, value)| match value {
            Value::String(text) => Ok((key.clone(), text.clone())),
            _ => err("parameters must be a string map"),
        })
        .collect()
}

pub fn to_value(params: &Params) -> Value {
    Value::Object(params.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect())
}

/// Validate (and normalise empty I2..I5 away); returns the cleaned map.
pub fn validate(version: &str, params: &Params, mtu: u64) -> Result<Params, ObfuscationError> {
    if !VERSIONS.contains(&version) {
        return err(format!("unknown version {version}"));
    }
    let clean: Params = params
        .iter()
        .filter(|(k, v)| !(I_KEYS.contains(&k.as_str()) && v.is_empty()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let mut extra: Vec<&String> = clean.keys().filter(|key| !allowed(version, key)).collect();
    extra.sort();
    if let Some(first) = extra.first() {
        return err(format!("{first} is not valid for {version}"));
    }
    let mut missing: Vec<&str> = required(version).into_iter().filter(|key| !clean.contains_key(*key)).collect();
    missing.sort_unstable();
    if let Some(first) = missing.first() {
        return err(format!("{first} is required for {version}"));
    }

    int(&clean, "Jc", 1, 128)?;
    let jmin = int(&clean, "Jmin", 1, mtu)?;
    let jmax = int(&clean, "Jmax", 1, mtu)?;
    if jmin >= jmax {
        return err("Jmin must be below Jmax");
    }
    let mut s: IndexMap<&str, u64> = IndexMap::new();
    for name in ["S1", "S2", "S3", "S4"] {
        if clean.contains_key(name) {
            s.insert(name, int(&clean, name, 0, 1132)?);
        }
    }
    if s["S1"] + 56 == s["S2"] {
        return err("S1 + 56 must differ from S2");
    }

    let mut heads = Vec::new();
    for i in 1..=4 {
        let key = format!("H{i}");
        heads.push(parse_range(&clean[key.as_str()], &key)?);
    }
    let floor = if version == "3.1" { 1 } else { 5 };
    for (i, (lo, hi)) in heads.iter().enumerate() {
        if *lo < floor {
            return err(format!("H{} must be at least {floor}", i + 1));
        }
        if version == "1.5" && lo != hi {
            return err(format!("H{} must be a single value for 1.5", i + 1));
        }
    }
    for (i, a) in heads.iter().enumerate() {
        if heads[i + 1..].iter().any(|b| a.0 <= b.1 && b.0 <= a.1) {
            return err("H1..H4 must not overlap");
        }
    }

    for key in I_KEYS {
        if clean.get(key).is_some_and(|value| !is_cps(value)) {
            return err(format!("{key} is not a valid CPS string"));
        }
    }

    if version == "3.1" {
        for name in ["S1", "S2", "S3", "S4"] {
            if s[name] < MIN_HEADER_PROTECTION_PADDING {
                return err(format!("{name} must be at least 12 with header protection"));
            }
        }
        if unb64(&clean["HeaderProtectionKey"]).is_err() {
            return err("HeaderProtectionKey must be a base64 32-byte key");
        }
        if let Some(padding) = clean.get("ContentPaddingAddition") {
            parse_range(padding, "ContentPaddingAddition")?;
        }
        for flag in ["RandomTrailers", "DisableCookies"] {
            if !matches!(clean.get(flag).map(String::as_str).unwrap_or("false"), "true" | "false") {
                return err(format!("{flag} must be true or false"));
            }
        }
    }
    Ok(clean)
}

/// What the panel gets: client key names, strings only, nothing disabled.
pub fn client_view(params: &Params) -> Params {
    params
        .iter()
        .filter(|(k, v)| !(matches!(k.as_str(), "RandomTrailers" | "DisableCookies") && v.as_str() != "true"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Device-level obfuscation lines in the order amneziawg-go's parser takes them.
///
/// S1..S4, H1..H4 and the header-protection key are collected by the parser and applied together
/// when the transaction ends, so they can sit anywhere inside one `set=1` block.
pub fn uapi_lines(params: &Params) -> Result<Vec<String>, crate::keys::KeyError> {
    let mut lines = Vec::new();
    for key in ["Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"] {
        if let Some(value) = params.get(key) {
            lines.push(format!("{}={value}", key.to_lowercase()));
        }
    }
    for key in I_KEYS {
        if let Some(value) = params.get(key).filter(|value| !value.is_empty()) {
            lines.push(format!("{}={value}", key.to_lowercase()));
        }
    }
    if let Some(key) = params.get("HeaderProtectionKey") {
        lines.push(format!("header_protection_key={}", hexkey(key)?));
    }
    if let Some(padding) = params.get("ContentPaddingAddition") {
        lines.push(format!("content_padding_addition={padding}"));
    }
    if params.get("RandomTrailers").map(String::as_str) == Some("true") {
        lines.push("random_trailers=true".into());
    }
    if params.get("DisableCookies").map(String::as_str) == Some("true") {
        lines.push("disable_cookies=true".into());
    }
    Ok(lines)
}

/// The optional AWG_OBFUSCATION_FILE document (`{"2.0": {"I1": "...", "Jc": 6}}`), normalised.
pub fn load_overrides(raw: &Value) -> Result<IndexMap<String, Params>, ObfuscationError> {
    let Some(sections) = raw.as_object() else { return err("obfuscation file must be a JSON object") };
    let mut out = IndexMap::new();
    for (version, values) in sections {
        let values = match values.as_object() {
            Some(values) if VERSIONS.contains(&version.as_str()) => values,
            _ => return err(format!("obfuscation file: bad section {}", crate::util::py_repr(version))),
        };
        let mut params = Params::new();
        for (key, value) in values {
            let text = match value {
                Value::Bool(flag) => (if *flag { "true" } else { "false" }).to_string(),
                Value::String(text) => text.clone(),
                Value::Number(number) if number.is_i64() || number.is_u64() => number.to_string(),
                _ => return err(format!("obfuscation file: bad value for {key}")),
            };
            params.insert(key.clone(), text);
        }
        out.insert(version.clone(), params);
    }
    Ok(out)
}

pub fn apply_overrides(version: &str, base: &Params, overrides: &Params, mtu: u64) -> Result<Params, ObfuscationError> {
    let mut merged = base.clone();
    for (key, value) in overrides {
        merged.insert(key.clone(), value.clone());
    }
    validate(version, &merged, mtu)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    pub fn params(pairs: &[(&str, &str)]) -> Params {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn generated(version: &str, seed: u64) -> Params {
        generate(version, 1280, &mut SeededRng(seed)).unwrap()
    }

    fn num(params: &Params, key: &str) -> u64 {
        params[key].parse().unwrap()
    }

    #[test]
    fn generated_parameters_are_valid_and_deterministic_for_a_seed() {
        for version in VERSIONS {
            let first = generated(version, 1);
            assert_eq!(first, generated(version, 1));
            assert_ne!(first, generated(version, 2));
            assert_eq!(validate(version, &first, 1280).unwrap(), first);
            for seed in 0..60 {
                let params = generated(version, seed);
                assert!(num(&params, "Jmax") <= 1280 && num(&params, "Jmin") < num(&params, "Jmax"));
                assert_ne!(num(&params, "S1") + 56, num(&params, "S2"));
                assert!((4..=8).contains(&num(&params, "Jc")));
                assert!(params["I1"].starts_with("<b 0xc") && params["I1"].contains("<t>"));
            }
        }
    }

    #[test]
    fn version_1_5_has_distinct_single_values_and_no_s3_s4() {
        let params = generated("1.5", 3);
        let heads: Vec<&String> = (1..=4).map(|i| &params[format!("H{i}").as_str()]).collect();
        let distinct: std::collections::BTreeSet<&&String> = heads.iter().collect();
        assert_eq!(distinct.len(), 4);
        assert!(heads.iter().all(|h| h.bytes().all(|b| b.is_ascii_digit()) && h.parse::<u64>().unwrap() > 4));
        assert!(!params.contains_key("S3") && !params.contains_key("HeaderProtectionKey"));
    }

    #[test]
    fn version_2_0_headers_are_wide_non_overlapping_ranges() {
        for seed in 0..40 {
            let params = generated("2.0", seed);
            let mut ranges: Vec<(u64, u64)> = (1..=4)
                .map(|i| {
                    let (lo, hi) = params[format!("H{i}").as_str()].split_once('-').unwrap();
                    (lo.parse().unwrap(), hi.parse().unwrap())
                })
                .collect();
            ranges.sort_unstable();
            assert!(ranges.iter().all(|(lo, hi)| hi - lo >= 1000 && *lo > 4));
            assert!((0..3).all(|i| ranges[i].1 < ranges[i + 1].0));
            assert!(params.contains_key("S3") && params.contains_key("S4"));
        }
    }

    #[test]
    fn version_3_1_header_protection_constraints() {
        let params = generated("3.1", 5);
        assert_eq!(
            (1..=4).map(|i| params[format!("H{i}").as_str()].as_str()).collect::<Vec<_>>(),
            ["1", "2", "3", "4"]
        );
        assert!((1..=4).all(|i| num(&params, &format!("S{i}")) >= 12));
        assert_eq!(unb64(&params["HeaderProtectionKey"]).unwrap().len(), 32);
        assert_eq!(params["ContentPaddingAddition"], "0-32");
        let view = client_view(&params);
        assert!(!view.contains_key("RandomTrailers") && !view.contains_key("DisableCookies"));
    }

    #[test]
    fn invalid_parameters_are_rejected() {
        for (version, change, message) in [
            ("1.5", vec![("S1", "100"), ("S2", "156")], "S1 + 56"),
            ("1.5", vec![("H1", "10"), ("H2", "10")], "overlap"),
            ("1.5", vec![("H1", "1")], "at least 5"),
            ("1.5", vec![("H1", "10-20")], "single value"),
            ("1.5", vec![("S3", "20")], "not valid"),
            ("1.5", vec![("Jmax", "2000")], "Jmax"),
            ("1.5", vec![("Jmin", "90"), ("Jmax", "50")], "Jmin"),
            ("1.5", vec![("I1", "<x 1>")], "CPS"),
            ("2.0", vec![("H1", "10-5000"), ("H2", "4000-9000")], "overlap"),
            ("3.1", vec![("S3", "11")], "at least 12"),
            ("3.1", vec![("HeaderProtectionKey", "short")], "HeaderProtectionKey"),
            ("3.1", vec![("RandomTrailers", "yes")], "RandomTrailers"),
        ] {
            let mut params = generated(version, 9);
            params.extend(change.iter().map(|(k, v)| (k.to_string(), v.to_string())));
            let error = validate(version, &params, 1280).unwrap_err();
            assert!(error.0.contains(message), "{version} {change:?}: {error}");
        }
    }

    #[test]
    fn uapi_lines_per_version_are_exact() {
        let v15 = params(&[
            ("Jc", "5"),
            ("Jmin", "10"),
            ("Jmax", "70"),
            ("S1", "20"),
            ("S2", "30"),
            ("H1", "11"),
            ("H2", "12"),
            ("H3", "13"),
            ("H4", "14"),
            ("I1", "<r 8>"),
        ]);
        assert_eq!(
            uapi_lines(&v15).unwrap(),
            ["jc=5", "jmin=10", "jmax=70", "s1=20", "s2=30", "h1=11", "h2=12", "h3=13", "h4=14", "i1=<r 8>"]
        );
        let key: Vec<u8> = (0..32).collect();
        let mut v31 = v15.clone();
        v31.extend(params(&[
            ("S3", "13"),
            ("S4", "14"),
            ("H1", "1"),
            ("H2", "2"),
            ("H3", "3"),
            ("H4", "4"),
            ("ContentPaddingAddition", "0-32"),
            ("RandomTrailers", "true"),
        ]));
        v31.insert("HeaderProtectionKey".into(), b64(&key));
        v31.shift_remove("I1");
        assert_eq!(
            uapi_lines(&v31).unwrap(),
            [
                "jc=5".to_string(),
                "jmin=10".into(),
                "jmax=70".into(),
                "s1=20".into(),
                "s2=30".into(),
                "s3=13".into(),
                "s4=14".into(),
                "h1=1".into(),
                "h2=2".into(),
                "h3=3".into(),
                "h4=4".into(),
                format!("header_protection_key={}", crate::keys::hex(&key)),
                "content_padding_addition=0-32".into(),
                "random_trailers=true".into(),
            ]
        );
    }

    #[test]
    fn overrides_are_normalised() {
        assert!(load_overrides(&json!({"9.9": {}})).is_err());
        assert!(load_overrides(&json!([])).is_err());
        assert!(load_overrides(&json!({"2.0": {"Jc": 1.5}})).is_err());
        let loaded = load_overrides(&json!({"2.0": {"Jc": 6, "RandomTrailers": true}})).unwrap();
        assert_eq!(loaded["2.0"], params(&[("Jc", "6"), ("RandomTrailers", "true")]));
    }

    #[test]
    fn cps_strings_follow_the_grammar() {
        for good in ["<r 8>", "<b 0xc30000000112><r 18><b 0x0000><t><r 86>", "<rc 1234><rd 1><c>", "<t>"] {
            assert!(is_cps(good), "{good}");
        }
        for bad in ["", "<x 1>", "<b 0x>", "<b 0xabc>", "<r 12345>", "<r >", "<t", "<t>x", "<r 8> ", "<R 8>"] {
            assert!(!is_cps(bad), "{bad}");
        }
    }
}
