//! Ported from `tests/test_version_agent_upstream.py`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use super::*;

const PANEL_DOWNLOAD: &str = "https://github.com/dubr1k/proxy-control/releases/download";
const TELEMT_REG: &str = "https://ghcr.io/v2/samnet-dev/mtproxymax-telemt";
const TELEMT_RELEASES_URL: &str = "https://api.github.com/repos/telemt/telemt/releases?per_page=10";
const TELEMT_DOWNLOAD: &str = "https://github.com/telemt/telemt/releases/download";
const GHCR_TOKEN: &str = "https://ghcr.io/token?scope=repository:samnet-dev/mtproxymax-telemt:pull";

fn xray_releases() -> Value {
    json!([
        {"tag_name": "v26.4.1", "prerelease": false, "draft": false, "published_at": "2026-04-01T00:00:00Z",
         "assets": [{"name": "Xray-linux-64.zip", "browser_download_url": "https://github.com/XTLS/Xray-core/releases/download/v26.4.1/Xray-linux-64.zip"},
                    {"name": "Xray-linux-64.zip.dgst", "browser_download_url": "https://github.com/XTLS/Xray-core/releases/download/v26.4.1/Xray-linux-64.zip.dgst"}]},
        {"tag_name": "v26.5.3", "prerelease": true, "draft": false, "published_at": "2026-05-03T00:00:00Z",
         "assets": [{"name": "Xray-linux-64.zip", "browser_download_url": "https://github.com/XTLS/Xray-core/releases/download/v26.5.3/Xray-linux-64.zip"},
                    {"name": "Xray-linux-64.zip.dgst", "browser_download_url": "https://github.com/XTLS/Xray-core/releases/download/v26.5.3/Xray-linux-64.zip.dgst"}]},
        {"tag_name": "v26.6.0", "prerelease": true, "draft": true, "published_at": "2026-06-01T00:00:00Z", "assets": []},
    ])
}

fn mieru_releases() -> Value {
    json!([
        {"tag_name": "v3.37.0", "prerelease": false, "draft": false, "published_at": "2026-03-01T00:00:00Z",
         "assets": [{"name": "mita_3.37.0_linux_amd64.tar.gz", "browser_download_url": "https://github.com/enfein/mieru/releases/download/v3.37.0/mita_3.37.0_linux_amd64.tar.gz"},
                    {"name": "mita_3.37.0_linux_amd64.tar.gz.sha256.txt", "browser_download_url": "https://github.com/enfein/mieru/releases/download/v3.37.0/mita_3.37.0_linux_amd64.tar.gz.sha256.txt"}]},
    ])
}

fn panel_releases() -> Value {
    json!([
        {"tag_name": "v0.11.0-beta.1", "prerelease": true, "draft": false, "published_at": "2026-09-21T00:00:00Z",
         "assets": [{"name": "proxy-control-v0.11.0-beta.1.tar.gz", "browser_download_url": format!("{PANEL_DOWNLOAD}/v0.11.0-beta.1/proxy-control-v0.11.0-beta.1.tar.gz")},
                    {"name": "SHA256SUMS", "browser_download_url": format!("{PANEL_DOWNLOAD}/v0.11.0-beta.1/SHA256SUMS")},
                    {"name": "release-manifest.json", "browser_download_url": format!("{PANEL_DOWNLOAD}/v0.11.0-beta.1/release-manifest.json")}]},
        {"tag_name": "v0.10.0-beta.1", "prerelease": true, "draft": false, "published_at": "2026-09-20T00:00:00Z",
         "assets": [{"name": "proxy-control-v0.10.0-beta.1.tar.gz", "browser_download_url": format!("{PANEL_DOWNLOAD}/v0.10.0-beta.1/proxy-control-v0.10.0-beta.1.tar.gz")},
                    {"name": "SHA256SUMS", "browser_download_url": format!("{PANEL_DOWNLOAD}/v0.10.0-beta.1/SHA256SUMS")}]},
        {"tag_name": "v0.12.0-beta.1", "prerelease": true, "draft": true, "published_at": null, "assets": []},
    ])
}

fn panel_sums() -> String {
    format!(
        "{}  proxy-control-v0.11.0-beta.1.tar.gz\n{}  release-manifest.json\n{}  sbom.spdx.json\n",
        "1".repeat(64),
        "2".repeat(64),
        "3".repeat(64)
    )
}

fn body(value: &Value) -> Fetched {
    Fetched::ok(value.to_string())
}

fn with_digest(digest: &str) -> Fetched {
    let mut answer = Fetched::ok("{}");
    answer.headers.insert("Docker-Content-Digest".into(), digest.into());
    answer
}

/// `fetcher_from(table)`: canned answers by URL, every requested URL recorded.
#[derive(Clone, Default)]
struct Table {
    answers: BTreeMap<String, Fetched>,
    seen: Arc<Mutex<Vec<String>>>,
}

impl Table {
    fn with(mut self, url: impl Into<String>, answer: Fetched) -> Table {
        self.answers.insert(url.into(), answer);
        self
    }

    fn without(mut self, url: &str) -> Table {
        self.answers.remove(url);
        self
    }

    fn seen(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}

impl Fetcher for Table {
    fn fetch(&self, url: &str, _headers: &[(&str, &str)], _maximum: u64) -> Result<Fetched, UpstreamError> {
        self.seen.lock().unwrap().push(url.to_string());
        self.answers.get(url).cloned().ok_or_else(|| UpstreamError(format!("unexpected url {url}")))
    }
}

fn versions(result: &Value) -> Vec<&str> {
    result["candidates"].as_array().unwrap().iter().map(|c| c["version"].as_str().unwrap()).collect()
}

#[test]
fn parsers_read_the_published_digests() {
    assert_eq!(
        parse_dgst(&format!("MD5= x\nSHA1= y\nSHA2-256= {}\nSHA2-512= z\n", "a".repeat(64))).unwrap(),
        "a".repeat(64)
    );
    assert_eq!(parse_dgst(&format!("SHA256= {}", "A".repeat(64))).unwrap(), "a".repeat(64));
    assert_eq!(
        parse_sha256_txt(&format!("{}  mita_3.37.0_linux_amd64.tar.gz\n", "b".repeat(64))).unwrap(),
        "b".repeat(64)
    );
    assert!(parse_dgst("nothing here").is_err());
    assert!(parse_sha256_txt("nothing here").is_err());
    // `\b…\b`: a longer hex run is not a digest.
    assert!(parse_sha256_txt(&"a".repeat(65)).is_err());
    assert_eq!(parse_sha256_txt(&format!("x {} y", "C".repeat(64))).unwrap(), "c".repeat(64));
}

#[test]
fn parse_sha256sums_picks_the_line_of_the_named_file() {
    assert_eq!(parse_sha256sums(&panel_sums(), "proxy-control-v0.11.0-beta.1.tar.gz").unwrap(), "1".repeat(64));
    assert_eq!(
        parse_sha256sums(&format!("{} *archive.tar.gz\n", "A".repeat(64)), "archive.tar.gz").unwrap(),
        "a".repeat(64)
    );
    assert!(parse_sha256sums(&panel_sums(), "proxy-control-v0.12.0-beta.1.tar.gz")
        .unwrap_err()
        .0
        .contains("SHA256SUMS"));
    assert!(parse_sha256sums("xyz  proxy-control-v0.11.0-beta.1.tar.gz\n", "proxy-control-v0.11.0-beta.1.tar.gz")
        .unwrap_err()
        .0
        .contains("SHA256SUMS"));
}

#[test]
fn panel_candidate_is_the_release_archive_with_its_sha256sums_line() {
    let fetch = Table::default()
        .with("https://api.github.com/repos/dubr1k/proxy-control/releases?per_page=10", body(&panel_releases()))
        .with(format!("{PANEL_DOWNLOAD}/v0.11.0-beta.1/SHA256SUMS"), Fetched::ok(panel_sums()));
    let result = check_component("panel", Some("0.10.0-beta.1"), &fetch, false).unwrap();
    assert_eq!(
        (&result["latest"], &result["installable"], &result["reason"]),
        (&json!("0.11.0-beta.1"), &json!(true), &json!(null))
    );
    assert_eq!(
        result["candidates"],
        json!([{"version": "0.11.0-beta.1", "tag": "v0.11.0-beta.1", "kind": "release", "source": "upstream",
                "url": format!("{PANEL_DOWNLOAD}/v0.11.0-beta.1/proxy-control-v0.11.0-beta.1.tar.gz"),
                "sha256": "1".repeat(64), "published_at": "2026-09-21T00:00:00Z"}])
    );
    // The SHA256SUMS of the installed release is never fetched.
    assert!(!fetch.seen().contains(&format!("{PANEL_DOWNLOAD}/v0.10.0-beta.1/SHA256SUMS")));
    assert_eq!(check_component("panel", Some("0.11.0-beta.1"), &fetch, false).unwrap()["candidates"], json!([]));
}

#[test]
fn panel_release_without_sha256sums_is_visible_but_not_installable() {
    let mut releases = panel_releases();
    let first = releases[0].clone();
    let mut only = first.clone();
    only["assets"] = json!([first["assets"][0]]);
    releases = json!([only]);
    let fetch = Table::default()
        .with("https://api.github.com/repos/dubr1k/proxy-control/releases?per_page=10", body(&releases));
    assert_eq!(
        check_component("panel", Some("0.10.0-beta.1"), &fetch, false).unwrap(),
        json!({"latest": "0.11.0-beta.1", "installable": false, "reason": "no_published_digest", "candidates": []})
    );
}

#[test]
fn compare_versions_orders_numerically_and_prereleases_lower() {
    assert!(compare_versions("26.4.1", "26.3.27") > 0);
    assert_eq!(compare_versions("3.37.0", "3.37.0"), 0);
    assert!(compare_versions("2.12.0-beta.1", "2.12.0") < 0);
    assert_eq!(compare_versions("3.4", "3.4.0"), 0);
    assert!(compare_versions("3.10.0", "3.9.9") > 0);
    assert!(compare_versions("1.99999999999999999999999", "1.9") > 0);
}

#[test]
fn compare_versions_matches_the_golden_vectors() {
    let vectors: Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/host-golden/vectors/compare-versions.json"))
            .unwrap();
    for case in vectors.as_array().unwrap() {
        let (a, b) = (case["a"].as_str().unwrap(), case["b"].as_str().unwrap());
        let mut expected = case["compare"]["ok"].as_i64().unwrap() as i32;
        if !a.is_ascii() {
            // Python's isdigit()/int() read Arabic-Indic digits; the port reads ASCII only.
            expected = compare_versions("0.0", b);
        }
        assert_eq!(compare_versions(a, b), expected, "{a:?} vs {b:?}");
    }
}

#[test]
fn xray_candidate_carries_the_dgst_hash_and_counts_xtls_prereleases_but_no_draft() {
    let fetch = Table::default()
        .with("https://api.github.com/repos/XTLS/Xray-core/releases?per_page=10", body(&xray_releases()))
        .with(
            "https://github.com/XTLS/Xray-core/releases/download/v26.4.1/Xray-linux-64.zip.dgst",
            Fetched::ok(format!("SHA2-256= {}\n", "a".repeat(64))),
        )
        .with(
            "https://github.com/XTLS/Xray-core/releases/download/v26.5.3/Xray-linux-64.zip.dgst",
            Fetched::ok(format!("SHA2-256= {}\n", "b".repeat(64))),
        );
    let result = check_component("xray", Some("26.3.27"), &fetch, true).unwrap();
    assert_eq!(
        (&result["latest"], &result["installable"], &result["reason"]),
        (&json!("26.5.3"), &json!(true), &json!(null))
    );
    assert_eq!(versions(&result), ["26.5.3", "26.4.1"]);
    let candidate = &result["candidates"][1];
    assert_eq!(candidate["sha256"], "a".repeat(64));
    assert_eq!(candidate["source"], "upstream");
    assert_eq!(
        candidate["archive"],
        json!({"format": "zip", "members": {"xray": "xray", "geoip.dat": "geoip.dat", "geosite.dat": "geosite.dat"}})
    );
    assert!(candidate["url"].as_str().unwrap().ends_with("/v26.4.1/Xray-linux-64.zip"));
    assert_eq!((&candidate["tag"], &candidate["published_at"]), (&json!("v26.4.1"), &json!("2026-04-01T00:00:00Z")));
}

#[test]
fn mita_candidate_reads_sha256_txt_and_names_the_tar_member() {
    let fetch = Table::default()
        .with("https://api.github.com/repos/enfein/mieru/releases?per_page=10", body(&mieru_releases()))
        .with(
            "https://github.com/enfein/mieru/releases/download/v3.37.0/mita_3.37.0_linux_amd64.tar.gz.sha256.txt",
            Fetched::ok(format!("{}  mita_3.37.0_linux_amd64.tar.gz\n", "b".repeat(64))),
        );
    let result = check_component("mita", Some("3.36.0"), &fetch, false).unwrap();
    assert_eq!(result["candidates"].as_array().unwrap().len(), 1);
    assert_eq!(result["candidates"][0]["archive"], json!({"format": "tar.gz", "member": "mita"}));
    assert_eq!(result["candidates"][0]["sha256"], "b".repeat(64));
}

#[test]
fn every_published_mita_with_a_digest_is_offered() {
    for version in ["3.38.0", "4.0.0"] {
        let base =
            format!("https://github.com/enfein/mieru/releases/download/v{version}/mita_{version}_linux_amd64.tar.gz");
        let mut release = mieru_releases()[0].clone();
        release["tag_name"] = json!(format!("v{version}"));
        release["assets"] = json!([
            {"name": format!("mita_{version}_linux_amd64.tar.gz"), "browser_download_url": base},
            {"name": format!("mita_{version}_linux_amd64.tar.gz.sha256.txt"), "browser_download_url": format!("{base}.sha256.txt")}]);
        let fetch = Table::default()
            .with("https://api.github.com/repos/enfein/mieru/releases?per_page=10", body(&json!([release])))
            .with(
                format!("{base}.sha256.txt"),
                Fetched::ok(format!("{}  mita_{version}_linux_amd64.tar.gz\n", "c".repeat(64))),
            );
        let result = check_component("mita", Some("3.37.0"), &fetch, false).unwrap();
        assert_eq!((&result["installable"], &result["reason"]), (&json!(true), &json!(null)));
        assert_eq!(versions(&result), [version]);
    }
}

#[test]
fn release_without_a_digest_file_is_visible_but_not_installable() {
    let mut release = mieru_releases()[0].clone();
    release["assets"] = json!([release["assets"][0]]);
    let fetch = Table::default()
        .with("https://api.github.com/repos/enfein/mieru/releases?per_page=10", body(&json!([release])));
    assert_eq!(
        check_component("mita", Some("3.36.0"), &fetch, false).unwrap(),
        json!({"latest": "3.37.0", "installable": false, "reason": "no_published_digest", "candidates": []})
    );
}

#[test]
fn asset_hosted_outside_the_repository_download_path_is_refused() {
    let mut release = mieru_releases()[0].clone();
    release["assets"] = json!([
        {"name": "mita_3.37.0_linux_amd64.tar.gz", "browser_download_url": "https://github.com/evil/repo/releases/download/v3.37.0/mita_3.37.0_linux_amd64.tar.gz"},
        release["assets"][1]]);
    let fetch = Table::default()
        .with("https://api.github.com/repos/enfein/mieru/releases?per_page=10", body(&json!([release])));
    let error = check_component("mita", Some("3.36.0"), &fetch, false).unwrap_err();
    assert!(error.0.contains("release download"), "{error}");
}

#[test]
fn telemt_candidate_is_the_registry_manifest_digest() {
    let fetch = Table::default()
        .with(GHCR_TOKEN, Fetched::ok(r#"{"token": "t"}"#))
        .with(
            format!("{TELEMT_REG}/tags/list?n=100"),
            Fetched::ok(r#"{"tags": ["3.4.24", "3.4.25-51e58b5", "latest"]}"#),
        )
        .with(format!("{TELEMT_REG}/manifests/3.4.25-51e58b5"), with_digest(&format!("sha256:{}", "c".repeat(64))));
    let result = check_component("telemt", Some("3.4.24"), &fetch, false).unwrap();
    assert_eq!(
        result["candidates"],
        json!([{"version": "3.4.25", "kind": "image", "source": "upstream", "tag": "3.4.25-51e58b5",
                "image": format!("ghcr.io/samnet-dev/mtproxymax-telemt@sha256:{}", "c".repeat(64)), "published_at": null}])
    );
    assert_eq!((&result["latest"], &result["installable"]), (&json!("3.4.25"), &json!(true)));
}

fn naive_table(releases: Value) -> Table {
    Table::default()
        .with("https://api.github.com/repos/caddyserver/caddy/releases?per_page=10", body(&releases))
        .with("https://api.github.com/repos/klzgrad/forwardproxy/commits/naive", body(&json!({"sha": "d".repeat(40)})))
        .with(
            "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/caddy:pull",
            Fetched::ok(r#"{"token": "t"}"#),
        )
}

#[test]
fn naive_candidate_is_a_build_with_the_builder_digest_and_forwardproxy_commit() {
    let fetch = naive_table(json!([{"tag_name": "v2.12.0", "prerelease": false, "draft": false,
                                     "published_at": "2026-02-01T00:00:00Z", "assets": []}]))
    .with(
        "https://registry-1.docker.io/v2/library/caddy/manifests/2.12.0-builder",
        with_digest(&format!("sha256:{}", "e".repeat(64))),
    );
    let result = check_component("naive", Some("2.11.4"), &fetch, false).unwrap();
    let candidate = &result["candidates"][0];
    assert_eq!(result["candidates"].as_array().unwrap().len(), 1);
    assert_eq!(candidate["kind"], "build");
    assert_eq!(
        candidate["build"],
        json!({"caddy_version": "2.12.0", "builder_image": format!("caddy:2.12.0-builder@sha256:{}", "e".repeat(64)),
               "forwardproxy_commit": "d".repeat(40)})
    );
    assert_eq!((&candidate["source"], &candidate["version"]), (&json!("upstream"), &json!("2.12.0")));
}

#[test]
fn older_releases_are_candidates_too_but_only_a_newer_one_is_an_update() {
    let fetch = Table::default()
        .with("https://api.github.com/repos/XTLS/Xray-core/releases?per_page=10", body(&xray_releases()))
        .with(
            "https://github.com/XTLS/Xray-core/releases/download/v26.4.1/Xray-linux-64.zip.dgst",
            Fetched::ok(format!("SHA2-256= {}\n", "a".repeat(64))),
        );
    let result = check_component("xray", Some("26.5.3"), &fetch, true).unwrap();
    assert_eq!(versions(&result), ["26.4.1"]);
    assert_eq!(
        (&result["installable"], &result["reason"], &result["latest"]),
        (&json!(false), &json!(null), &json!("26.5.3"))
    );
    assert_eq!(
        check_component("xray", Some("26.3.27"), &fetch, false).unwrap(),
        json!({"latest": null, "installable": false, "reason": "router_not_installed", "candidates": []})
    );
}

#[test]
fn an_older_release_without_a_digest_is_skipped_without_a_reason() {
    let mut release = mieru_releases()[0].clone();
    release["tag_name"] = json!("v3.36.0");
    release["assets"] = json!([]);
    let fetch = Table::default()
        .with("https://api.github.com/repos/enfein/mieru/releases?per_page=10", body(&json!([release])));
    assert_eq!(
        check_component("mita", Some("3.37.0"), &fetch, false).unwrap(),
        json!({"latest": "3.36.0", "installable": false, "reason": null, "candidates": []})
    );
}

#[test]
fn candidates_are_capped_at_the_six_newest_releases() {
    let mut releases = Vec::new();
    let mut table = Table::default();
    for minor in 30..40 {
        let version = format!("3.{minor}.0");
        let base =
            format!("https://github.com/enfein/mieru/releases/download/v{version}/mita_{version}_linux_amd64.tar.gz");
        let mut release = mieru_releases()[0].clone();
        release["tag_name"] = json!(format!("v{version}"));
        release["assets"] = json!([
            {"name": format!("mita_{version}_linux_amd64.tar.gz"), "browser_download_url": base},
            {"name": format!("mita_{version}_linux_amd64.tar.gz.sha256.txt"), "browser_download_url": format!("{base}.sha256.txt")}]);
        releases.push(release);
        table = table.with(
            format!("{base}.sha256.txt"),
            Fetched::ok(format!("{}  mita_{version}_linux_amd64.tar.gz\n", "c".repeat(64))),
        );
    }
    table = table.with("https://api.github.com/repos/enfein/mieru/releases?per_page=10", body(&Value::Array(releases)));
    let result = check_component("mita", Some("3.37.0"), &table, false).unwrap();
    assert_eq!(versions(&result), ["3.39.0", "3.38.0", "3.36.0", "3.35.0", "3.34.0", "3.33.0"]);
    assert_eq!(result["installable"], true);
}

#[test]
fn telemt_lists_older_images_and_skips_the_installed_one() {
    let fetch = Table::default()
        .with(GHCR_TOKEN, Fetched::ok(r#"{"token": "t"}"#))
        .with(
            format!("{TELEMT_REG}/tags/list?n=100"),
            Fetched::ok(r#"{"tags": ["3.4.24", "3.4.25-51e58b5", "latest"]}"#),
        )
        .with(format!("{TELEMT_REG}/manifests/3.4.24"), with_digest(&format!("sha256:{}", "c".repeat(64))));
    let result = check_component("telemt", Some("3.4.25"), &fetch, false).unwrap();
    assert_eq!(versions(&result), ["3.4.24"]);
    assert_eq!(result["installable"], false);
}

#[test]
fn naive_offers_the_three_newest_caddy_releases_but_the_installed_one() {
    let caddy: Vec<Value> = [10, 11, 12, 13]
        .iter()
        .map(|minor| json!({"tag_name": format!("v2.{minor}.0"), "prerelease": false, "draft": false, "published_at": null, "assets": []}))
        .collect();
    let mut fetch = naive_table(Value::Array(caddy));
    for minor in [10, 11, 12, 13] {
        fetch = fetch.with(
            format!("https://registry-1.docker.io/v2/library/caddy/manifests/2.{minor}.0-builder"),
            with_digest(&format!("sha256:{}", "e".repeat(64))),
        );
    }
    let result = check_component("naive", Some("2.12.0"), &fetch, false).unwrap();
    assert_eq!(versions(&result), ["2.13.0", "2.11.0", "2.10.0"]);
    assert_eq!(result["installable"], true);
}

#[test]
fn the_panel_is_never_offered_backwards() {
    let fetch = Table::default()
        .with("https://api.github.com/repos/dubr1k/proxy-control/releases?per_page=10", body(&panel_releases()));
    assert_eq!(check_component("panel", Some("0.12.0-beta.1"), &fetch, false).unwrap()["candidates"], json!([]));
}

#[test]
fn rate_limited_github_becomes_an_error_and_check_all_keeps_going() {
    let fetch = Table::default()
        .with(
            "https://api.github.com/repos/XTLS/Xray-core/releases?per_page=10",
            Fetched { status: 403, ..Fetched::default() },
        )
        .with("https://api.github.com/repos/enfein/mieru/releases?per_page=10", body(&mieru_releases()))
        .with(
            "https://github.com/enfein/mieru/releases/download/v3.37.0/mita_3.37.0_linux_amd64.tar.gz.sha256.txt",
            Fetched::ok(format!("{}\n", "b".repeat(64))),
        );
    let current: BTreeMap<String, Option<String>> =
        [("xray", Some("26.3.27")), ("mita", Some("3.36.0")), ("telemt", None), ("naive", None)]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.map(String::from)))
            .collect();
    let result = check_all(&current, &fetch, true);
    assert_eq!(result.keys().cloned().collect::<Vec<_>>(), ["mita", "naive", "panel", "telemt", "xray"]);
    assert!(result["xray"]["last_error"].as_str().unwrap().contains("403"));
    assert_eq!(result["xray"]["last_error"], "upstream answered 403 for /repos/XTLS/Xray-core/releases");
    assert_eq!(result["xray"]["candidates"], json!([]));
    assert_eq!(result["mita"]["candidates"][0]["version"], "3.37.0");
    assert!(result["mita"].get("last_error").is_none());
    assert!(result["telemt"]["last_error"].as_str().unwrap().contains("unexpected url"));
}

#[test]
fn fetch_https_refuses_hosts_outside_the_allowlist() {
    let fetcher = HttpsFetcher::new();
    for url in ["https://example.com/x", "http://api.github.com/x", "https://user:pw@api.github.com/x"] {
        let error = fetcher.fetch(url, &[], 10).unwrap_err();
        assert!(error.0.contains("host"), "{url}: {error}");
    }
    assert!(UPSTREAM_HOSTS.contains(&"api.github.com"));
}

#[test]
fn redirect_handler_refuses_a_hop_outside_the_allowlist() {
    // The per-hop check lives in pc_host::net (followed hop by hop there); the rule is the same.
    for hop in ["https://evil.example/asset", "http://github.com/asset"] {
        assert!(pc_host::net::check_host(hop, &["github.com"]).is_err(), "{hop}");
    }
    assert!(pc_host::net::check_host("https://github.com/asset", &["github.com"]).is_ok());
}

#[test]
fn an_older_image_the_registry_does_not_answer_for_is_skipped() {
    let fetch = Table::default()
        .with(GHCR_TOKEN, Fetched::ok(r#"{"token": "t"}"#))
        .with(format!("{TELEMT_REG}/tags/list?n=100"), Fetched::ok(r#"{"tags": ["3.4.23", "3.4.24", "3.4.25"]}"#))
        .with(format!("{TELEMT_REG}/manifests/3.4.23"), with_digest(&format!("sha256:{}", "c".repeat(64))));
    let result = check_component("telemt", Some("3.4.25"), &fetch, false).unwrap();
    assert_eq!(versions(&result), ["3.4.23"]);
}

// --- Telemt `build` candidates -------------------------------------------------------------

fn telemt_release(tag: &str, digest: Option<&str>, size: i64, draft: bool, prerelease: bool, name: &str) -> Value {
    let mut asset =
        json!({"name": name, "size": size, "browser_download_url": format!("{TELEMT_DOWNLOAD}/{tag}/{name}")});
    if let Some(digest) = digest {
        asset["digest"] = json!(digest);
    }
    json!({"tag_name": tag, "draft": draft, "prerelease": prerelease, "published_at": "2026-10-05T15:39:55Z", "assets": [asset]})
}

fn auto_digest(tag: &str) -> String {
    if tag == "3.5.14" {
        "sha256:feb1d8779de0b86c6c43d1b871020ec94b11fad9fec5612b07b278edfd2181ff".into()
    } else {
        format!("sha256:{}", "e".repeat(64))
    }
}

fn release(tag: &str) -> Value {
    telemt_release(tag, Some(&auto_digest(tag)), 16810696, false, false, "telemt")
}

fn telemt_table(releases: Vec<Value>, tags: &[&str]) -> Table {
    let mut table = Table::default()
        .with(GHCR_TOKEN, Fetched::ok(r#"{"token": "t"}"#))
        .with(format!("{TELEMT_REG}/tags/list?n=100"), body(&json!({"tags": tags})))
        .with(TELEMT_RELEASES_URL, body(&Value::Array(releases)));
    for tag in tags {
        let digest = format!("sha256:{}", if tag.starts_with("3.5.9") { "9" } else { "8" }.repeat(64));
        table = table.with(format!("{TELEMT_REG}/manifests/{tag}"), with_digest(&digest));
    }
    table
}

const TAGS: [&str; 2] = ["3.5.8-aaaaaaa", "3.5.9-bbbbbbb"];

#[test]
fn telemt_build_candidate_from_the_real_github_payload_shape() {
    let fetch = telemt_table(vec![release("3.5.14")], &TAGS);
    let result = check_component("telemt", Some("3.5.9"), &fetch, false).unwrap();
    let builds: Vec<&Value> =
        result["candidates"].as_array().unwrap().iter().filter(|c| c["kind"] == "build").collect();
    assert_eq!(
        builds,
        [&json!({"version": "3.5.14", "tag": "3.5.14", "kind": "build", "source": "upstream",
                 "base_image": format!("ghcr.io/samnet-dev/mtproxymax-telemt@sha256:{}", "9".repeat(64)),
                 "url": format!("{TELEMT_DOWNLOAD}/3.5.14/telemt"),
                 "sha256": "feb1d8779de0b86c6c43d1b871020ec94b11fad9fec5612b07b278edfd2181ff",
                 "published_at": "2026-10-05T15:39:55Z"})]
    );
    assert_eq!((&result["latest"], &result["installable"]), (&json!("3.5.14"), &json!(true)));
    assert!(result.get("last_error").is_none());
    assert_eq!(versions(&result), ["3.5.14", "3.5.8"]);
}

#[test]
fn telemt_build_skips_missing_digest_prerelease_draft_oversize_and_wrong_asset() {
    let releases = vec![
        telemt_release("3.5.20", None, 16810696, false, false, "telemt"),
        telemt_release("3.5.19", Some("md5:abc"), 16810696, false, false, "telemt"),
        telemt_release("3.5.18", Some(&auto_digest("3.5.18")), 16810696, false, true, "telemt"),
        telemt_release("3.5.17", Some(&auto_digest("3.5.17")), 16810696, true, false, "telemt"),
        telemt_release("3.5.16", Some(&auto_digest("3.5.16")), 64 * 1024 * 1024 + 1, false, false, "telemt"),
        telemt_release("3.5.15", Some(&auto_digest("3.5.15")), 16810696, false, false, "telemt-arm"),
        release("v3.5.13"),
        release("3.5.12"),
    ];
    let result = check_component("telemt", Some("3.5.9"), &telemt_table(releases, &TAGS), false).unwrap();
    let builds: Vec<&str> = result["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["kind"] == "build")
        .map(|c| c["version"].as_str().unwrap())
        .collect();
    assert_eq!(builds, ["3.5.12"]);
    assert_eq!(result["latest"], "3.5.12");
}

#[test]
fn telemt_build_is_not_offered_when_the_registry_has_the_same_version() {
    let fetch = telemt_table(vec![release("3.5.9"), release("3.5.10")], &TAGS);
    let result = check_component("telemt", Some("3.5.8"), &fetch, false).unwrap();
    let kinds: BTreeMap<&str, &str> = result["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["version"].as_str().unwrap(), c["kind"].as_str().unwrap()))
        .collect();
    assert_eq!(kinds, BTreeMap::from([("3.5.10", "build"), ("3.5.9", "image")]));
}

#[test]
fn telemt_build_base_is_the_newest_registry_image_even_when_it_is_installed() {
    let result =
        check_component("telemt", Some("3.5.9"), &telemt_table(vec![release("3.5.14")], &TAGS), false).unwrap();
    assert!(result["candidates"][0]["base_image"].as_str().unwrap().ends_with(&"9".repeat(64)));
}

#[test]
fn telemt_build_offers_nothing_when_the_registry_is_unreadable() {
    let table = telemt_table(vec![release("3.5.14")], &TAGS).without(GHCR_TOKEN);
    let current = BTreeMap::from([("telemt".to_string(), Some("3.5.9".to_string()))]);
    let result = &check_all(&current, &table, false)["telemt"];
    assert_eq!(result["candidates"], json!([]));
    assert!(pc_common::pyvalue::truthy(&result["last_error"]));
}

#[test]
fn telemt_build_failure_of_github_keeps_the_registry_candidates() {
    let table = telemt_table(vec![], &TAGS).without(TELEMT_RELEASES_URL);
    let result = check_component("telemt", Some("3.5.8"), &table, false).unwrap();
    let kinds: Vec<&str> =
        result["candidates"].as_array().unwrap().iter().map(|c| c["kind"].as_str().unwrap()).collect();
    assert_eq!(kinds, ["image"]);
    assert!(pc_common::pyvalue::truthy(&result["last_error"]));
}

#[test]
fn telemt_build_asset_outside_the_repository_download_path_is_reported() {
    let mut bad = release("3.5.14");
    bad["assets"][0]["browser_download_url"] = json!("https://github.com/evil/telemt/releases/download/3.5.14/telemt");
    let result = check_component("telemt", Some("3.5.8"), &telemt_table(vec![bad], &TAGS), false).unwrap();
    assert!(result["candidates"].as_array().unwrap().iter().all(|c| c["kind"] == "image"));
    assert!(result["last_error"].as_str().unwrap().contains("release download"));
}

#[test]
fn amneziawg_and_trusttunnel_keep_the_installed_release() {
    let tags = json!([
        {"name": "v3.1.20260828", "commit": {"sha": "a".repeat(40)}},
        {"name": "v1.0.20250101", "commit": {"sha": "b".repeat(40)}},
        {"name": "latest", "commit": {"sha": "c".repeat(40)}},
        {"name": "v2.0.0", "commit": {"sha": "short"}},
    ]);
    let fetch = Table::default()
        .with(format!("https://api.github.com/repos/{AMNEZIAWG_REPOSITORY}/tags?per_page=30"), body(&tags));
    let result = check_component("amneziawg", Some("3.1.20260828"), &fetch, false).unwrap();
    assert_eq!(versions(&result), ["3.1.20260828", "1.0.20250101"]);
    assert_eq!(result["installable"], false);
    assert_eq!(result["candidates"][0]["build"], json!({"commit": "a".repeat(40), "tag": "v3.1.20260828"}));

    let name = |tag: &str| format!("trusttunnel-{tag}-linux-x86_64.tar.gz");
    let asset = |tag: &str, digest: Value| {
        json!({"tag_name": tag, "draft": false, "prerelease": false, "published_at": "2026-10-01T00:00:00Z",
               "assets": [{"name": name(tag), "size": 1000, "digest": digest,
                           "browser_download_url": format!("https://github.com/{TRUSTTUNNEL_REPOSITORY}/releases/download/{tag}/{}", name(tag))}]})
    };
    let releases = json!([
        asset("v1.1.0", json!(format!("sha256:{}", "1".repeat(64)))),
        asset("v1.2.0", json!(null)),
        asset("v1.0.0", json!(format!("sha256:{}", "2".repeat(64))))
    ]);
    let fetch = Table::default()
        .with(format!("https://api.github.com/repos/{TRUSTTUNNEL_REPOSITORY}/releases?per_page=10"), body(&releases));
    let result = check_component("trusttunnel", Some("1.1.0"), &fetch, false).unwrap();
    assert_eq!(versions(&result), ["1.1.0", "1.0.0"]);
    assert_eq!(
        (&result["latest"], &result["installable"], &result["reason"]),
        (&json!("1.1.0"), &json!(false), &json!("no_published_digest"))
    );
    assert_eq!(result["candidates"][0]["sha256"], "1".repeat(64));
}

// --- ported from tests/test_version_agent_protocol_managers.py ---------------------------------

const TT: &str = "https://github.com/TrustTunnel/TrustTunnel/releases/download";
const AWG_URL: &str = "https://api.github.com/repos/amnezia-vpn/amneziawg-go/tags?per_page=30";
const TT_URL: &str = "https://api.github.com/repos/TrustTunnel/TrustTunnel/releases?per_page=10";

fn awg_tags() -> Value {
    json!([
        {"name": "v3.1.20260814", "commit": {"sha": format!("1b86b2ae0e49{}", "0".repeat(28))}},
        {"name": "v3.1.20260828", "commit": {"sha": "b5928efb6ca19f0153958460c3d141f04abc5c2e"}},
        {"name": "not-a-version", "commit": {"sha": "f".repeat(40)}},
        {"name": "v3.1.20260812", "commit": {"sha": "short"}},
    ])
}

fn tt_release(tag: &str, prerelease: bool, digest: Option<String>) -> Value {
    let name = format!("trusttunnel-{tag}-linux-x86_64.tar.gz");
    json!({"tag_name": tag, "draft": false, "prerelease": prerelease, "published_at": "2026-09-01T11:56:46Z",
           "assets": [{"name": name, "browser_download_url": format!("{TT}/{tag}/{name}"), "digest": digest, "size": 10_608_905},
                      {"name": format!("trusttunnel-{tag}-linux-aarch64.tar.gz"), "digest": format!("sha256:{}", "b".repeat(64))}]})
}

fn a_digest() -> Option<String> {
    Some(format!("sha256:{}", "a".repeat(64)))
}

#[test]
fn amneziawg_offers_tags_with_their_commits_newest_first_and_keeps_the_installed_one() {
    let fetch = Table::default().with(AWG_URL, body(&awg_tags()));
    let probe = check_component("amneziawg", Some("3.1.20260814"), &fetch, false).unwrap();
    assert_eq!((&probe["latest"], &probe["installable"]), (&json!("3.1.20260828"), &json!(true)));
    let candidates = probe["candidates"].as_array().unwrap();
    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[1]["version"], "3.1.20260814");
    assert!(candidates[1]["build"]["commit"].as_str().unwrap().starts_with("1b86b2ae0e49"));
    assert_eq!(
        candidates[0],
        json!({"version": "3.1.20260828", "tag": "v3.1.20260828", "kind": "build", "source": "upstream",
               "build": {"commit": "b5928efb6ca19f0153958460c3d141f04abc5c2e", "tag": "v3.1.20260828"}, "published_at": null})
    );
    let current = check_component("amneziawg", Some("3.1.20260828"), &fetch, false).unwrap();
    assert_eq!(current["installable"], false);
    assert_eq!(versions(&current), ["3.1.20260828", "3.1.20260814"]);
}

#[test]
fn trusttunnel_offers_stable_releases_with_the_x86_64_digest_and_never_a_beta() {
    let releases = json!([
        tt_release("v1.3.0-beta.2", true, a_digest()),
        tt_release("v1.2.0", false, a_digest()),
        tt_release("v1.1.0", false, Some(format!("sha256:{}", "9".repeat(64))))
    ]);
    let probe =
        check_component("trusttunnel", Some("1.1.0"), &Table::default().with(TT_URL, body(&releases)), false).unwrap();
    assert_eq!((&probe["latest"], &probe["installable"]), (&json!("1.2.0"), &json!(true)));
    let (candidate, installed) = (&probe["candidates"][0], &probe["candidates"][1]);
    assert_eq!((&installed["version"], &installed["sha256"]), (&json!("1.1.0"), &json!("9".repeat(64))));
    assert_eq!(
        (&candidate["version"], &candidate["sha256"], &candidate["kind"]),
        (&json!("1.2.0"), &json!("a".repeat(64)), &json!("build"))
    );
    assert_eq!(candidate["url"], format!("{TT}/v1.2.0/trusttunnel-v1.2.0-linux-x86_64.tar.gz"));
}

#[test]
fn a_trusttunnel_release_without_a_digest_is_visible_but_not_installable() {
    let releases = json!([tt_release("v1.2.0", false, None), tt_release("v1.1.0", false, a_digest())]);
    let probe =
        check_component("trusttunnel", Some("1.1.0"), &Table::default().with(TT_URL, body(&releases)), false).unwrap();
    assert_eq!((&probe["installable"], &probe["reason"]), (&json!(false), &json!("no_published_digest")));
    assert_eq!(versions(&probe), ["1.1.0"]);
}

#[test]
fn a_trusttunnel_asset_outside_its_repository_is_refused() {
    let mut bad = tt_release("v1.2.0", false, a_digest());
    bad["assets"][0]["browser_download_url"] =
        json!("https://github.com/someone/else/releases/download/v1.2.0/x.tar.gz");
    assert!(check_component("trusttunnel", Some("1.1.0"), &Table::default().with(TT_URL, body(&json!([bad]))), false)
        .is_err());
}

#[test]
fn check_all_probes_the_protocol_managers_only_on_a_host_that_runs_them() {
    let fetch = Table::default();
    let without = check_all(&BTreeMap::from([("telemt".to_string(), None)]), &fetch, false);
    assert!(!without.contains_key("amneziawg") && !without.contains_key("trusttunnel"));
    let current =
        BTreeMap::from([("telemt".to_string(), None), ("amneziawg".to_string(), Some("3.1.20260828".to_string()))]);
    let with_awg = check_all(&current, &fetch, false);
    assert!(with_awg["amneziawg"]["last_error"].as_str().unwrap().contains("unexpected url"));
    assert!(!with_awg.contains_key("trusttunnel"));
}
