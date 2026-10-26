//! `pytext` against Python 3.13.5 (Unicode 15.1) — `fixtures/pytext.json`, made by
//! `fixtures/generators/gen_pytext.py` in the panel image.

use std::sync::OnceLock;

use panel_core::pytext::{self, IpAddress};
use serde_json::Value;

fn fixture() -> &'static Value {
    static FIXTURE: OnceLock<Value> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/pytext.json")).unwrap();
        serde_json::from_str(&text).unwrap()
    })
}

fn section(name: &str) -> &'static Vec<Value> {
    let items = fixture()[name].as_array().unwrap_or_else(|| panic!("no section {name}"));
    assert!(!items.is_empty(), "empty section {name}");
    items
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap()
}

fn strings(value: &Value) -> Vec<&str> {
    value.as_array().unwrap().iter().map(text).collect()
}

#[test]
fn fixture_comes_from_unicode_15_1() {
    assert_eq!(fixture()["unicode"], "15.1.0");
}

#[test]
fn split_and_strip() {
    for entry in section("split") {
        let input = text(&entry[0]);
        assert_eq!(pytext::split(input), strings(&entry[1]), "split {input:?}");
        assert_eq!(pytext::strip(input), text(&entry[2]), "strip {input:?}");
    }
}

#[test]
fn whitespace_table_is_exactly_isspace() {
    let mut expected = std::collections::BTreeSet::new();
    for entry in section("split") {
        let input = text(&entry[0]);
        // The fixture holds "x<space>y" for every whitespace code point.
        let chars: Vec<char> = input.chars().collect();
        if chars.len() == 3 && chars[0] == 'x' && chars[2] == 'y' && entry[1].as_array().unwrap().len() == 2 {
            expected.insert(chars[1]);
        }
    }
    let actual: std::collections::BTreeSet<char> =
        (0..=0x10FFFFu32).filter_map(char::from_u32).filter(|c| pytext::is_space(*c)).collect();
    assert_eq!(actual.len(), 29);
    assert_eq!(actual, expected);
}

#[test]
fn isprintable() {
    for entry in section("isprintable") {
        let input = text(&entry[0]);
        assert_eq!(pytext::is_printable(input), entry[1].as_bool().unwrap(), "isprintable {input:?}");
    }
}

#[test]
fn nfc_and_nfkc() {
    for entry in section("nfc") {
        let input = text(&entry[0]);
        assert_eq!(pytext::nfc(input), text(&entry[1]), "NFC {input:?}");
        assert_eq!(pytext::nfkc(input), text(&entry[2]), "NFKC {input:?}");
    }
}

#[test]
fn len_and_slices() {
    for entry in section("slice") {
        let input = text(&entry[0]);
        assert_eq!(pytext::len(input) as u64, entry[1].as_u64().unwrap(), "len {input:?}");
        for slice in entry[2].as_array().unwrap() {
            let bound = |value: &Value| value.as_i64().map(|index| index as isize);
            assert_eq!(pytext::slice(input, bound(&slice[0]), bound(&slice[1])), text(&slice[2]), "{input:?}[{slice}]");
        }
    }
}

#[test]
fn quote_quote_plus_and_unquote() {
    for entry in section("quote") {
        let (input, safe) = (text(&entry[0]), text(&entry[1]));
        assert_eq!(pytext::quote(input, safe), text(&entry[2]), "quote({input:?}, safe={safe:?})");
        assert_eq!(pytext::quote_plus(input, safe), text(&entry[3]), "quote_plus({input:?}, safe={safe:?})");
    }
    for entry in section("quote_default") {
        assert_eq!(pytext::quote_path(text(&entry[0])), text(&entry[1]));
    }
    for entry in section("unquote") {
        assert_eq!(pytext::unquote(text(&entry[0])), text(&entry[1]), "unquote {:?}", entry[0]);
    }
    for entry in section("urlencode") {
        let pairs: Vec<(String, String)> = entry[0]
            .as_array()
            .unwrap()
            .iter()
            .map(|pair| (text(&pair[0]).to_string(), text(&pair[1]).to_string()))
            .collect();
        assert_eq!(pytext::urlencode(&pairs), text(&entry[1]));
    }
}

#[test]
fn ip_address_parsing_text_and_tables() {
    let mut valid = 0;
    for entry in section("ip") {
        let input = text(&entry[0]);
        let parsed = pytext::ip_address(input);
        if entry[1].is_null() {
            assert!(parsed.is_err(), "{input:?} should be refused, got {parsed:?}");
            continue;
        }
        valid += 1;
        let address = parsed.unwrap_or_else(|error| panic!("{input:?}: {error}"));
        assert_eq!(u64::from(address.version()), entry[1].as_u64().unwrap(), "{input:?}");
        assert_eq!(address.to_string(), text(&entry[2]), "str {input:?}");
        let facts = [
            address.is_global(),
            address.is_private(),
            address.is_multicast(),
            address.is_loopback(),
            address.is_link_local(),
            address.is_unspecified(),
            address.is_reserved(),
        ];
        let expected: Vec<bool> = entry.as_array().unwrap()[3..].iter().map(|v| v.as_bool().unwrap()).collect();
        assert_eq!(
            facts.to_vec(),
            expected,
            "is_global/private/multicast/loopback/link_local/unspecified/reserved of {input:?}"
        );
        // A resolver answer classifies the same as the parsed text.
        let resolved = IpAddress::from(address.to_std());
        assert_eq!(resolved.is_global(), address.is_global(), "{input:?} via std::net");
    }
    assert!(valid > 500, "only {valid} valid addresses");
    assert_eq!(pytext::ip_address("fe80::1%eth0").unwrap(), IpAddress::V6(0xfe80 << 112 | 1, Some("eth0".to_string())));
    assert_eq!(
        pytext::ip_address("1.2.3").unwrap_err().to_string(),
        "'1.2.3' does not appear to be an IPv4 or IPv6 address"
    );
}

#[test]
fn urlsplit_and_its_properties() {
    for entry in section("urlsplit") {
        let input = text(&entry["input"]);
        let parsed = pytext::urlsplit(input);
        if let Some(error) = entry.get("error") {
            assert_eq!(parsed.unwrap_err().to_string(), text(error), "{input:?}");
            continue;
        }
        let parts = parsed.unwrap_or_else(|error| panic!("{input:?}: {error}"));
        assert_eq!(parts.scheme, text(&entry["scheme"]), "scheme {input:?}");
        assert_eq!(parts.netloc, text(&entry["netloc"]), "netloc {input:?}");
        assert_eq!(parts.path, text(&entry["path"]), "path {input:?}");
        assert_eq!(parts.query, text(&entry["query"]), "query {input:?}");
        assert_eq!(parts.fragment, text(&entry["fragment"]), "fragment {input:?}");
        assert_eq!(parts.username(), entry["username"].as_str(), "username {input:?}");
        assert_eq!(parts.password(), entry["password"].as_str(), "password {input:?}");
        assert_eq!(parts.hostname().as_deref(), entry["hostname"].as_str(), "hostname {input:?}");
        match entry.get("port_error") {
            Some(error) => assert_eq!(parts.port().unwrap_err().to_string(), text(error), "port {input:?}"),
            None => assert_eq!(parts.port().unwrap().map(u64::from), entry["port"].as_u64(), "port {input:?}"),
        }
    }
}

#[test]
fn repr_and_lower() {
    for entry in section("repr") {
        assert_eq!(pytext::repr(text(&entry[0])), text(&entry[1]), "repr {:?}", entry[0]);
    }
    for entry in section("lower") {
        assert_eq!(pytext::lower(text(&entry[0])), text(&entry[1]), "lower {:?}", entry[0]);
    }
}

#[test]
fn int_and_float_parsing() {
    for entry in section("int") {
        let input = text(&entry["input"]);
        match (entry.get("ok"), pytext::int_from_str(input)) {
            (Some(expected), Ok(value)) => assert_eq!(Some(value), expected.as_i64(), "int({input:?})"),
            // Python's ints are unbounded; the port refuses what does not fit an i64.
            (Some(expected), Err(error)) => {
                assert!(expected.as_i64().is_none(), "int({input:?}) refused: {error}");
                assert!(error.to_string().starts_with("int() value out of range"), "{error}");
            }
            (None, Ok(value)) => panic!("int({input:?}) = {value}, Python refused it"),
            (None, Err(error)) => assert_eq!(error.to_string(), text(&entry["error"]), "int({input:?})"),
        }
    }
    for entry in section("float") {
        let input = text(&entry["input"]);
        match (entry.get("ok"), pytext::float_from_str(input)) {
            (Some(expected), Ok(value)) => {
                assert_eq!(panel_core::pyjson::float_repr(value), text(expected), "float({input:?})")
            }
            (Some(_), Err(error)) => panic!("float({input:?}) refused: {error}"),
            (None, Ok(value)) => panic!("float({input:?}) = {value}, Python refused it"),
            (None, Err(error)) => assert_eq!(error.to_string(), text(&entry["error"]), "float({input:?})"),
        }
    }
}

#[test]
fn decimal_digits_of_every_script() {
    assert_eq!(pytext::decimal('7'), Some(7));
    assert_eq!(pytext::decimal('\u{663}'), Some(3));
    assert_eq!(pytext::decimal('\u{1D7CE}'), Some(0));
    assert_eq!(pytext::decimal('a'), None);
    assert_eq!(pytext::decimal('\u{B2}'), None);
}
