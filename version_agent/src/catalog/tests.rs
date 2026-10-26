//! Ported from `tests/test_version_agent.py` (catalog cases).

use serde_json::{json, Value};

use super::*;

const TELEMT_IMAGE: &str =
    "ghcr.io/example/telemt@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PANEL_URL: &str =
    "https://github.com/dubr1k/proxy-control/releases/download/v0.11.0-beta.1/proxy-control-v0.11.0-beta.1.tar.gz";
const BUILD_URL: &str = "https://github.com/telemt/telemt/releases/download/3.5.14/telemt";

fn build_base() -> String {
    format!("ghcr.io/samnet-dev/mtproxymax-telemt@sha256:{}", "d".repeat(64))
}

fn build_sha() -> String {
    pc_host::fs::sha256_hex(b"\x7fELF-telemt-3.5.14")
}

fn load(document: Value) -> Result<Catalog, CatalogError> {
    parse_catalog(document.to_string().as_bytes())
}

fn error_of(document: Value) -> String {
    load(document).expect_err("the catalog is refused").0
}

#[test]
fn catalog_requires_immutable_artifacts() {
    let message = error_of(json!({"schema": 1, "components": {
        "telemt": [{"version": "latest", "kind": "image", "image": "ghcr.io/example/telemt:latest"}],
        "naive": [], "mita": []}}));
    assert!(message.contains("immutable image"), "{message}");
}

#[test]
fn catalog_accepts_archive_members_and_the_xray_component() {
    let loaded = load(json!({"schema": 1, "components": {
        "xray": [{"version": "26.4.1", "kind": "binary",
                  "url": "https://github.com/XTLS/Xray-core/releases/download/v26.4.1/Xray-linux-64.zip",
                  "sha256": "a".repeat(64),
                  "archive": {"format": "zip", "members": {"xray": "xray", "geoip.dat": "geoip.dat", "geosite.dat": "geosite.dat"}}}],
        "mita": [{"version": "3.37.0", "kind": "binary",
                  "url": "https://github.com/enfein/mieru/releases/download/v3.37.0/mita_3.37.0_linux_amd64.tar.gz",
                  "sha256": "b".repeat(64), "archive": {"format": "tar.gz", "member": "mita"}}]}}))
    .unwrap();
    let entry = loaded.entry("xray", "26.4.1").unwrap();
    assert_eq!(entry.archive.as_ref().unwrap()["members"]["geosite.dat"], "geosite.dat");
    assert_eq!(entry.source, "catalog");
    let mita = loaded.entry("mita", "3.37.0").unwrap().public();
    assert_eq!(mita["archive"], json!({"format": "tar.gz", "member": "mita"}));
    assert_eq!(mita["source"], "catalog");
}

#[test]
fn catalog_rejects_archive_members_that_escape() {
    let message = error_of(json!({"schema": 1, "components": {"mita": [{
        "version": "3.37.0", "kind": "binary", "url": "https://github.com/enfein/mieru/releases/download/v3.37.0/x.tar.gz",
        "sha256": "b".repeat(64), "archive": {"format": "tar.gz", "member": "../mita"}}]}}));
    assert!(message.contains("archive member"), "{message}");
}

#[test]
fn catalog_requires_the_xray_member_set_and_a_single_member_elsewhere() {
    let message = error_of(json!({"schema": 1, "components": {"xray": [{
        "version": "26.4.1", "kind": "binary", "url": "https://github.com/XTLS/Xray-core/releases/download/v26.4.1/x.zip",
        "sha256": "a".repeat(64), "archive": {"format": "zip", "member": "xray"}}]}}));
    assert!(message.contains("members"), "{message}");
    let message = error_of(json!({"schema": 1, "components": {"naive": [{
        "version": "2.12.0", "kind": "binary", "url": "https://example.com/caddy",
        "sha256": "a".repeat(64), "source": "somewhere"}]}}));
    assert!(message.contains("source"), "{message}");
}

#[test]
fn catalog_accepts_a_caddy_build_entry() {
    let build = json!({"caddy_version": "2.12.0", "builder_image": format!("caddy:2.12.0-builder@sha256:{}", "c".repeat(64)),
                       "forwardproxy_commit": "d".repeat(40)});
    let loaded =
        load(json!({"schema": 1, "components": {"naive": [{"version": "2.12.0", "kind": "build", "build": build}]}}))
            .unwrap();
    let entry = loaded.entry("naive", "2.12.0").unwrap();
    assert_eq!(entry.kind, "build");
    assert_eq!(entry.build.as_ref().unwrap()["caddy_version"], "2.12.0");
    assert_eq!(entry.public()["build"]["forwardproxy_commit"], "d".repeat(40));
    let message = error_of(
        json!({"schema": 1, "components": {"mita": [{"version": "2.12.0", "kind": "build", "build": build}]}}),
    );
    assert!(message.contains("unsupported artifact kind"), "{message}");
}

#[test]
fn catalog_accepts_a_panel_release_entry_and_refuses_it_elsewhere() {
    let release = json!({"version": "0.11.0-beta.1", "kind": "release", "url": PANEL_URL, "sha256": "1".repeat(64),
                         "source": "upstream"});
    let entry = entry_from_value("panel", &release).unwrap();
    assert_eq!(
        (entry.kind.as_str(), entry.url.as_deref(), entry.source.as_str()),
        ("release", Some(PANEL_URL), "upstream")
    );
    assert_eq!(entry.sha256.as_deref(), Some("1".repeat(64).as_str()));
    assert_eq!(
        Value::Object(entry.public()),
        json!({"version": "0.11.0-beta.1", "kind": "release", "source": "upstream", "url": PANEL_URL, "sha256": "1".repeat(64)})
    );
    let mut catalog_release = release.clone();
    catalog_release["source"] = json!("catalog");
    let loaded = load(json!({"schema": 1, "components": {"panel": [catalog_release]}})).unwrap();
    assert_eq!(loaded.entry("panel", "0.11.0-beta.1").unwrap().source, "catalog");
    let with = |key: &str, value: Value| {
        let mut changed = release.clone();
        changed[key] = value;
        changed
    };
    let refused = |component: &str, raw: &Value| entry_from_value(component, raw).unwrap_err().0;
    assert!(refused("panel", &with("url", json!("http://github.com/x.tar.gz"))).contains("HTTPS"));
    assert!(refused("panel", &with("sha256", json!("nope"))).contains("SHA-256"));
    assert!(refused("panel", &with("archive", json!({"format": "tar.gz", "member": "VERSION"})))
        .contains("unknown release field"));
    assert!(refused("mita", &release).contains("unsupported artifact kind"));
    let binary = json!({"version": "0.11.0-beta.1", "kind": "binary", "url": PANEL_URL, "sha256": "1".repeat(64)});
    assert!(refused("panel", &binary).contains("unsupported artifact kind"));
}

#[test]
fn catalog_rejects_non_https_binary_sources() {
    let message = error_of(json!({"schema": 1, "components": {"telemt": [], "mita": [], "naive": [
        {"version": "2.11.4", "kind": "binary", "url": "http://artifacts.example.com/caddy", "sha256": "b".repeat(64)}]}}));
    assert!(message.contains("HTTPS"), "{message}");
}

fn build_entry(changes: Value) -> Value {
    let mut entry = json!({"version": "3.5.14", "kind": "build", "base_image": build_base(), "url": BUILD_URL,
                           "sha256": build_sha()});
    for (key, value) in changes.as_object().unwrap() {
        entry[key] = value.clone();
    }
    entry
}

#[test]
fn catalog_accepts_a_telemt_build_and_publishes_its_fields() {
    let loaded = load(json!({"schema": 1, "components": {"telemt": [
        build_entry(json!({})), {"version": "3.4.25", "kind": "image", "image": TELEMT_IMAGE}]}}))
    .unwrap();
    assert_eq!(
        Value::Object(loaded.entry("telemt", "3.5.14").unwrap().public()),
        json!({"version": "3.5.14", "kind": "build", "source": "catalog", "base_image": build_base(), "url": BUILD_URL,
               "sha256": build_sha()})
    );
    assert_eq!(loaded.entry("telemt", "3.4.25").unwrap().public()["image"], TELEMT_IMAGE);
}

#[test]
fn catalog_rejects_a_malformed_telemt_build() {
    let cases = [
        json!({"base_image": format!("ghcr.io/other/telemt@sha256:{}", "d".repeat(64))}),
        json!({"base_image": "ghcr.io/samnet-dev/mtproxymax-telemt:3.5.9"}),
        json!({"base_image": format!("docker.io/ghcr.io/samnet-dev/mtproxymax-telemt@sha256:{}", "d".repeat(64))}),
        json!({"url": "https://example.com/telemt/telemt/releases/download/3.5.14/telemt"}),
        json!({"url": "https://github.com/telemt/telemt/releases/download/3.5.13/telemt"}),
        json!({"url": "https://github.com/telemt/telemt/releases/download/3.5.14/telemt?x=1"}),
        json!({"url": "http://github.com/telemt/telemt/releases/download/3.5.14/telemt"}),
        json!({"sha256": "A".repeat(64)}),
        json!({"sha256": "abc"}),
        json!({"version": "latest", "url": "https://github.com/telemt/telemt/releases/download/latest/telemt"}),
        json!({"image": TELEMT_IMAGE}),
    ];
    for bad in cases {
        let entry = build_entry(bad.clone());
        assert!(load(json!({"schema": 1, "components": {"telemt": [entry]}})).is_err(), "{bad}");
    }
}

#[test]
fn catalog_root_and_list_errors_keep_python_messages() {
    assert_eq!(parse_catalog(b"not json").unwrap_err().0, "version catalog unavailable");
    assert_eq!(error_of(json!([])), "version catalog must be an object");
    assert_eq!(
        error_of(json!({"schema": 1, "components": {}, "zzz": 1, "extra": 2})),
        "unknown catalog root field: extra"
    );
    assert_eq!(error_of(json!({"schema": 2, "components": {}})), "unsupported version catalog schema");
    assert_eq!(error_of(json!({"schema": 1, "components": []})), "unsupported version catalog schema");
    assert_eq!(error_of(json!({"schema": 1, "components": {"bogus": []}})), "unknown version catalog component");
    assert_eq!(error_of(json!({"schema": 1, "components": {"mita": {}}})), "mita catalog must be a list");
    let image = json!({"version": "3.4.25", "kind": "image", "image": TELEMT_IMAGE});
    assert_eq!(error_of(json!({"schema": 1, "components": {"telemt": [image, image]}})), "duplicate telemt version");
    assert_eq!(error_of(json!({"schema": 1, "components": {"telemt": [5]}})), "telemt catalog entry must be an object");
    assert_eq!(
        error_of(
            json!({"schema": 1, "components": {"telemt": [{"version": "1", "kind": "image", "image": TELEMT_IMAGE,
                                                                  "zeta": 1, "alpha": 2}]}})
        ),
        "unknown catalog field: alpha"
    );
    // Python's `raw.get("schema") != 1` lets `true` and `1.0` through.
    assert!(load(json!({"schema": true, "components": {}})).is_ok());
    assert!(load(json!({"schema": 1.0, "components": {}})).is_ok());
    let seed = include_bytes!("../../../tests/fixtures/host-golden/agent/seed/versions.json");
    assert!(parse_catalog(seed).unwrap().components.iter().all(|(_, entries)| entries.is_empty()));
}

#[test]
fn validators_match_the_python_regexes() {
    let vectors: Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/host-golden/vectors/validators-version.json"))
            .unwrap();
    for case in vectors.as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        // Python's `\d` matched Arabic-Indic digits; the Rust validators are ASCII (DIFFERENCES).
        let ascii = input.is_ascii();
        let expect = |key: &str| case[key].as_bool().unwrap() && ascii;
        assert_eq!(is_version(input), case["_VERSION"].as_bool().unwrap(), "_VERSION {input:?}");
        assert_eq!(is_dotted(input), expect("TELEMT_RELEASE_VERSION"), "dotted {input:?}");
        assert_eq!(is_dotted(input), expect("AMNEZIAWG_VERSION"), "awg {input:?}");
        assert_eq!(is_trusttunnel_version(input), expect("TRUSTTUNNEL_VERSION"), "tt {input:?}");
    }
    assert!(is_image(TELEMT_IMAGE));
    assert!(!is_image(&format!("@sha256:{}", "a".repeat(64))));
    assert!(is_image(&format!("caddy:2.12.0-builder@sha256:{}", "c".repeat(64))));
    assert!(!is_image(&format!("-caddy@sha256:{}", "c".repeat(64))));
    assert!(is_member("a/b.c") && !is_member("a//b") && !is_member("/a") && !is_member("a/../b") && !is_member(""));
    assert!(
        is_runtime_version(&"é".repeat(160)) && !is_runtime_version(&"é".repeat(161)) && !is_runtime_version("a\rb")
    );
}

// --- ported from tests/test_version_agent_protocol_managers.py ---------------------------------

const TT: &str = "https://github.com/TrustTunnel/TrustTunnel/releases/download";

#[test]
fn the_catalog_refuses_a_malformed_manager_build() {
    let cases = [
        (
            "amneziawg",
            json!({"version": "3.1.20260828", "kind": "build", "build": {"commit": "g".repeat(40), "tag": "v3.1.20260828"}}),
        ),
        (
            "amneziawg",
            json!({"version": "3.1.20260828", "kind": "build", "build": {"commit": "a".repeat(40), "tag": "v3.1.20260814"}}),
        ),
        (
            "amneziawg",
            json!({"version": "master", "kind": "build", "build": {"commit": "a".repeat(40), "tag": "vmaster"}}),
        ),
        (
            "trusttunnel",
            json!({"version": "1.2.0", "kind": "build", "url": format!("{TT}/v1.2.0/evil.tar.gz"), "sha256": "a".repeat(64)}),
        ),
        (
            "trusttunnel",
            json!({"version": "1.2.0", "kind": "build", "url": "https://example.com/trusttunnel-v1.2.0-linux-x86_64.tar.gz",
                               "sha256": "a".repeat(64)}),
        ),
        (
            "trusttunnel",
            json!({"version": "1.2.0", "kind": "build", "url": format!("{TT}/v1.2.0/trusttunnel-v1.2.0-linux-x86_64.tar.gz"),
                               "sha256": "XYZ"}),
        ),
    ];
    for (component, raw) in cases {
        assert!(entry_from_value(component, &raw).is_err(), "{component} {raw}");
    }
}

#[test]
fn the_catalog_takes_a_well_formed_manager_build() {
    let awg = entry_from_value(
        "amneziawg",
        &json!({"version": "3.1.20260828", "kind": "build", "source": "upstream",
                                                    "build": {"commit": "b".repeat(40), "tag": "v3.1.20260828"}}),
    )
    .unwrap();
    let tt = entry_from_value(
        "trusttunnel",
        &json!({"version": "1.3.0-beta.2", "kind": "build", "source": "catalog",
        "url": format!("{TT}/v1.3.0-beta.2/trusttunnel-v1.3.0-beta.2-linux-x86_64.tar.gz"), "sha256": "c".repeat(64)}),
    )
    .unwrap();
    assert_eq!(Value::Object(awg.build.unwrap()), json!({"commit": "b".repeat(40), "tag": "v3.1.20260828"}));
    assert_eq!(tt.sha256.as_deref(), Some("c".repeat(64).as_str()));
}
