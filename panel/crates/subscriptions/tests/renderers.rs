//! Byte and behaviour parity with `panel/tests/test_subscription_{renderers,names}.py`.
//! Goldens in `fixtures/` were recorded by `record_goldens.py` under Python 3.13.5.

use panel_model::protocols::{AccessArtifact, AutoRefresh};
use panel_model::subscriptions::{Manifest, ManifestGrant};
use panel_subscriptions::renderers::{self, Artifacts, Format, RenderOptions, MEDIA_TYPE_MANIFEST};
use panel_subscriptions::SubscriptionService;
use serde_json::{Map, Value};

fn fixture() -> (Manifest, Artifacts) {
    let case: Value = serde_json::from_str(include_str!("fixtures/case.json")).unwrap();
    let source = &case["manifest"];
    let grants = source["grants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|grant| ManifestGrant {
            grant_id: grant["grant_id"].as_str().unwrap().into(),
            protocol: grant["protocol"].as_str().unwrap().into(),
            node_id: grant["node_id"].as_str().unwrap().into(),
            endpoint_id: grant["endpoint_id"].as_str().unwrap().into(),
            runtime_username: grant["runtime_username"].as_str().unwrap().into(),
            secret_version: grant["secret_version"].as_i64().unwrap(),
            options: grant["options"].as_object().cloned().unwrap_or_else(Map::new),
            enabled: grant["enabled"].as_bool().unwrap(),
            valid_from: grant["valid_from"].as_i64(),
            valid_until: grant["valid_until"].as_i64(),
            node_name: grant["node_name"].as_str().unwrap().into(),
            label: grant["label"].as_str().unwrap().into(),
        })
        .collect();
    let manifest = Manifest::new(
        source["client_id"].as_str().unwrap(),
        source["client_name"].as_str().unwrap(),
        source["generation"].as_i64().unwrap(),
        grants,
    );
    let artifacts = case["artifacts"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(grant_id, items)| {
            let items = items
                .as_array()
                .unwrap()
                .iter()
                .map(|item| AccessArtifact {
                    kind: item["kind"].as_str().unwrap().into(),
                    label: item["label"].as_str().unwrap().into(),
                    media_type: item["media_type"].as_str().unwrap().into(),
                    value: item["value"].as_str().unwrap().into(),
                    auto_refresh: match item["auto_refresh"].as_str().unwrap() {
                        "supported" => AutoRefresh::Supported,
                        "unsupported" => AutoRefresh::Unsupported,
                        other => panic!("unknown auto_refresh {other}"),
                    },
                })
                .collect();
            (grant_id.clone(), items)
        })
        .collect();
    (manifest, artifacts)
}

fn golden(name: &str) -> Vec<u8> {
    std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)).unwrap()
}

#[test]
fn python_3135_goldens_match_every_renderer_and_variant() {
    let (manifest, artifacts) = fixture();
    for format in [Format::Raw, Format::Clash, Format::Manifest] {
        let actual = renderers::render(format, &manifest, &artifacts, &RenderOptions::default()).unwrap();
        assert_eq!(actual, golden(&format!("{}.golden", format.name())), "{}", format.name());
    }
    for client in ["karing", "singbox", "hiddify", "nekobox", "throne", "fork"] {
        let actual = renderers::render(Format::Singbox, &manifest, &artifacts, &RenderOptions::client(client)).unwrap();
        assert_eq!(actual, golden(&format!("singbox.{client}.golden")), "singbox/{client}");
    }
    for lang in ["ru", "en"] {
        let options = RenderOptions {
            url: "https://sub.example.com/s/TOKEN".into(),
            lang: lang.into(),
            updated_at: Some(1_800_000_000),
            ..RenderOptions::default()
        };
        let actual = renderers::render(Format::Html, &manifest, &artifacts, &options).unwrap();
        assert_eq!(actual, golden(&format!("html.{lang}.golden")), "html/{lang}");
    }
}

#[test]
fn python_3135_etag_goldens_match_every_renderer_variant() {
    let (manifest, _) = fixture();
    let expected: Value = serde_json::from_str(include_str!("fixtures/etags.json")).unwrap();
    for (key, etag) in expected.as_object().unwrap() {
        let (format, variant) = key.split_once(':').unwrap();
        let format = Format::from_name(format).unwrap();
        assert_eq!(
            &SubscriptionService::etag(&manifest, format.version(), variant).unwrap(),
            etag.as_str().unwrap(),
            "{key}"
        );
    }
}

#[test]
fn the_renderer_set_is_the_one_the_owner_decided() {
    assert_eq!(Format::ALL.map(|format| format.name()), ["manifest", "singbox", "clash", "raw", "html"]);
    assert_eq!(Format::Manifest.media_type(), MEDIA_TYPE_MANIFEST);
    assert!(Format::ALL.into_iter().all(|format| format.version() >= 1));
}

#[test]
fn disabled_and_credential_less_grants_never_become_links() {
    let (manifest, artifacts) = fixture();
    for format in Format::ALL {
        let text =
            String::from_utf8(renderers::render(format, &manifest, &artifacts, &RenderOptions::default()).unwrap())
                .unwrap();
        assert!(!text.contains("naive-pass-02"), "{}", format.name());
        if format == Format::Raw {
            assert!(text.lines().any(|line| line == "# disabled naive erin"));
            assert!(text.lines().any(|line| line == "# unsupported mieru dave: no stored credential"));
        }
        if format == Format::Clash {
            let proxies = text.split("proxy-control:").next().unwrap();
            assert!(!proxies.contains("erin") && !proxies.contains("dave"));
        }
    }
}

#[test]
fn the_official_singbox_variant_carries_naive_only() {
    let (manifest, artifacts) = fixture();
    let body = renderers::render(Format::Singbox, &manifest, &artifacts, &RenderOptions::client("singbox")).unwrap();
    let data: Value = serde_json::from_slice(&body).unwrap();
    let types: Vec<_> =
        data["outbounds"].as_array().unwrap().iter().map(|item| item["type"].as_str().unwrap()).collect();
    assert_eq!(types, ["naive"]);
    assert_eq!(data["proxy_control"]["client"], "singbox");
    assert!(renderers::render(Format::Singbox, &manifest, &artifacts, &RenderOptions::client("mihomo")).is_err());
}

#[test]
fn clash_lists_mieru_and_trusttunnel_with_quoted_scalars() {
    let (manifest, artifacts) = fixture();
    let text =
        String::from_utf8(renderers::render(Format::Clash, &manifest, &artifacts, &RenderOptions::default()).unwrap())
            .unwrap();
    let (proxies, tail) = text.split_once("proxy-control:").unwrap();
    assert!(proxies.contains("port-range: '8000-8010'"));
    assert!(proxies.contains("type: 'trusttunnel'"));
    assert!(proxies.contains("username: 'carol'\n    password: 'mieru-pass-01'"));
    assert!(!proxies.contains("type: 'naive'") && !proxies.contains("type: 'mtproxy'"));
    assert!(!text.contains('\t') && !text.contains('\r'));
    assert!(tail.contains("naiveproxy support") && tail.contains("MTProto"));
}

#[test]
fn manifest_json_carries_grants_artifacts_and_compatibility() {
    let (manifest, artifacts) = fixture();
    let body = renderers::render(Format::Manifest, &manifest, &artifacts, &RenderOptions::default()).unwrap();
    let data: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(data["version"], 1);
    assert_eq!(data["generation"], 3);
    assert_eq!(data["client_name"], "Sergey <b>&</b>");
    let grants = data["grants"].as_array().unwrap();
    let bob = grants.iter().find(|grant| grant["runtime_username"] == "bob").unwrap();
    assert_eq!(bob["artifacts"][0]["value"], "https://bob:naive-pass-01@naive.example.com");
    assert_eq!(bob["artifacts"][0]["auto_refresh"], "supported");
    let dave = grants.iter().find(|grant| grant["runtime_username"] == "dave").unwrap();
    assert_eq!(dave["artifacts"], serde_json::json!([]));
    assert_eq!(dave["unsupported"], "no stored credential");
    assert!(!String::from_utf8(body).unwrap().contains("secret_ref"));
}

#[test]
fn html_escapes_values_and_has_only_inline_assets() {
    let (manifest, artifacts) = fixture();
    let options = RenderOptions { url: "https://sub.example.com/s/TOKEN".into(), ..RenderOptions::default() };
    let text = String::from_utf8(renderers::render(Format::Html, &manifest, &artifacts, &options).unwrap()).unwrap();
    assert!(text.contains("Sergey &lt;b&gt;&amp;&lt;/b&gt;"));
    assert!(!text.contains("<b>&</b>"));
    assert!(text.contains("<meta name=\"robots\" content=\"noindex\">"));
    assert!(!text.to_lowercase().contains("<script src"));
    assert_eq!(text.to_lowercase().matches("<script").count(), 1);
    assert!(!text.contains("style=\"") && !text.contains("onclick"));
}

#[test]
fn a_body_over_the_size_limit_is_refused_not_truncated() {
    let (manifest, artifacts) = fixture();
    let options = RenderOptions { max_bytes: 64, ..RenderOptions::default() };
    for format in Format::ALL {
        let error = renderers::render(format, &manifest, &artifacts, &options).unwrap_err();
        assert!(error.to_string().contains("too large"), "{}: {error}", format.name());
    }
}

#[test]
fn too_many_grants_are_refused_without_leaking_credentials() {
    let (mut manifest, artifacts) = fixture();
    let one = manifest.grants[1].clone();
    manifest.grants = vec![one; 65];
    for format in Format::ALL {
        let error = renderers::render(format, &manifest, &artifacts, &RenderOptions::default()).unwrap_err();
        assert!(error.to_string().contains("too many grants"));
        assert!(!error.to_string().contains("naive-pass-01"));
    }
}

fn text(format: Format, manifest: &Manifest, artifacts: &Artifacts, options: &RenderOptions) -> String {
    String::from_utf8(renderers::render(format, manifest, artifacts, options).unwrap()).unwrap()
}

fn outbounds(manifest: &Manifest, artifacts: &Artifacts, client: &str) -> Vec<Value> {
    let body = renderers::render(Format::Singbox, manifest, artifacts, &RenderOptions::client(client)).unwrap();
    serde_json::from_slice::<Value>(&body).unwrap()["outbounds"].as_array().unwrap().clone()
}

#[test]
fn singbox_names_include_node_and_keep_credentials() {
    let (mut manifest, artifacts) = fixture();
    manifest.grants[3].node_name = "FRA-none".into();
    manifest.grants[4].node_name = "AMS-disabled".into();
    manifest.grants[5].node_name = "FRA-range".into();
    let outbounds = outbounds(&manifest, &artifacts, "karing");
    let naive = outbounds.iter().find(|item| item["type"] == "naive").unwrap();
    assert_eq!(naive["tag"], "AMS · Naive");
    assert_eq!(naive["username"], "bob");
    assert_eq!(naive["password"], "naive-pass-01");
    let mieru = outbounds.iter().find(|item| item["type"] == "mieru" && item["username"] == "carol").unwrap();
    assert_eq!(mieru["tag"], "FRA · Mieru · TCP 8443");
    assert_eq!(mieru["password"], "mieru-pass-01");
}

#[test]
fn duplicate_node_names_get_stable_unique_suffixes() {
    let (mut manifest, mut artifacts) = fixture();
    let mut second = manifest.grants[1].clone();
    second.grant_id = "g-naive-second".into();
    manifest.grants = vec![manifest.grants[1].clone(), second.clone()];
    artifacts.insert(second.grant_id.clone(), artifacts["g-naive"].clone());
    for grant in &mut manifest.grants {
        grant.node_name = "AMS".into();
    }
    let names = |manifest: &Manifest| {
        outbounds(manifest, &artifacts, "nekobox")
            .into_iter()
            .map(|item| item["tag"].as_str().unwrap().to_string())
            .collect::<std::collections::BTreeSet<_>>()
    };
    let before = names(&manifest);
    assert_eq!(before.len(), 2);
    assert!(before.iter().all(|name| name.contains(" [")));
    manifest.grants.reverse();
    assert_eq!(before, names(&manifest));
}

#[test]
fn clash_group_references_node_qualified_names() {
    let (manifest, artifacts) = fixture();
    let rendered = text(Format::Clash, &manifest, &artifacts, &RenderOptions::default());
    let group = rendered.split("proxy-groups:").nth(1).unwrap().split("proxy-control:").next().unwrap();
    for name in ["FRA · Mieru [", " · TCP 8443'", "TT · TrustTunnel ["] {
        assert!(group.contains(name), "{name}: {group}");
    }
}

#[test]
fn raw_links_have_names_without_changing_connection_fields() {
    let (mut manifest, artifacts) = fixture();
    manifest.grants[3].node_name = "FRA-none".into();
    manifest.grants[4].node_name = "AMS-disabled".into();
    manifest.grants[5].node_name = "FRA-range".into();
    let rendered = text(Format::Raw, &manifest, &artifacts, &RenderOptions::default());
    assert!(rendered.contains("naive+https://bob:naive-pass-01@naive.example.com:443#AMS%20%C2%B7%20Naive"));
    assert!(rendered.contains(
        "mierus://carol:mieru-pass-01@mieru.example.com?profile=FRA%20%C2%B7%20Mieru&port=8443&protocol=TCP"
    ));
    assert!(rendered.contains("tg://proxy?server=proxy.example.com&port=443&secret=ee00112233445566778899aabbccddeeff"));
}

#[test]
fn node_rename_invalidates_etag() {
    let (mut manifest, _) = fixture();
    let before = SubscriptionService::etag(&manifest, 4, "").unwrap();
    manifest.grants[0].node_name = "Amsterdam".into();
    let after = SubscriptionService::etag(&manifest, 4, "").unwrap();
    assert_ne!(before, after);
}

#[test]
fn node_rename_does_not_change_the_html_page_but_still_moves_the_etag() {
    let (mut manifest, artifacts) = fixture();
    manifest.grants = vec![manifest.grants[2].clone()];
    manifest.grants[0].enabled = false;
    let options = RenderOptions { url: "https://sub.example.com/s/TOKEN".into(), ..RenderOptions::default() };
    let before_body = text(Format::Html, &manifest, &artifacts, &options);
    let before = SubscriptionService::etag(&manifest, 5, "").unwrap();
    manifest.grants[0].node_name = "Amsterdam".into();
    let after_body = text(Format::Html, &manifest, &artifacts, &options);
    let after = SubscriptionService::etag(&manifest, 5, "").unwrap();
    assert_eq!(before_body, after_body);
    assert_ne!(before, after);
}

#[test]
fn node_name_is_internal_not_a_new_manifest_wire_field() {
    let (manifest, artifacts) = fixture();
    let rendered = text(Format::Manifest, &manifest, &artifacts, &RenderOptions::default());
    let value: Value = serde_json::from_str(&rendered).unwrap();
    assert_eq!(value["version"], 1);
    assert!(!rendered.contains("node_name"));
    assert!(value["grants"].as_array().unwrap().iter().all(|grant| grant.get("node_id").is_some()));
}

#[test]
fn canonically_equivalent_unicode_names_get_unique_suffixes() {
    let (mut manifest, mut artifacts) = fixture();
    let mut second = manifest.grants[1].clone();
    second.grant_id = "g-naive-second".into();
    manifest.grants = vec![manifest.grants[1].clone(), second.clone()];
    artifacts.insert(second.grant_id.clone(), artifacts["g-naive"].clone());
    manifest.grants[0].node_name = "Caf\u{e9}".into();
    manifest.grants[1].node_name = "Cafe\u{301}".into();
    let tags: Vec<_> = outbounds(&manifest, &artifacts, "karing")
        .into_iter()
        .map(|item| item["tag"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(tags.len(), 2);
    assert_ne!(tags[0], tags[1]);
    assert!(tags.iter().all(|tag| tag.starts_with("Caf\u{e9}")));
}

#[test]
fn untrusted_node_names_are_safe_in_all_display_formats() {
    let (mut manifest, artifacts) = fixture();
    manifest.grants = vec![manifest.grants[2].clone()];
    manifest.grants[0].node_name = "AMS's\n\u{202e}<script>".into();
    let clash = text(Format::Clash, &manifest, &artifacts, &RenderOptions::default());
    assert!(clash.contains("AMS’s <script> · Mieru"));
    assert!(!clash.contains('\u{202e}'));
    let raw = text(Format::Raw, &manifest, &artifacts, &RenderOptions::default());
    assert!(!raw.contains('\u{202e}') && raw.contains("AMS%E2%80%99s%20%3Cscript%3E"));
}

#[test]
fn the_page_starts_with_add_buttons_and_hides_qr() {
    let (manifest, artifacts) = fixture();
    let options = RenderOptions {
        url: "https://sub.example.com/s/TOKEN".into(),
        updated_at: Some(1_800_000_000),
        ..RenderOptions::default()
    };
    let page = text(Format::Html, &manifest, &artifacts, &options);
    let head = page.split("<h2>Все доступы</h2>").next().unwrap();
    assert!(head.contains("Подписка обновляется сама") && head.contains("Копировать ссылку подписки"));
    assert!(head.find("Добавить в Karing").unwrap() < head.find("Добавить в FlClash").unwrap());
    assert!(head.contains("<details class=\"qr\"><summary>Показать QR</summary>"));
    assert!(!head.contains("<details class=\"qr\" open"));
    assert!(page.contains("<footer>Обновлено 2027-01-15 08:00 UTC</footer>"));
}

#[test]
fn the_english_page_has_no_russian_chrome() {
    let (manifest, artifacts) = fixture();
    let options =
        RenderOptions { url: "https://sub.example.com/s/TOKEN".into(), lang: "en".into(), ..RenderOptions::default() };
    let page = text(Format::Html, &manifest, &artifacts, &options);
    assert!(page.contains("lang=\"en\"") && page.contains("Add to Karing"));
    assert!(page.contains("Manual setup data"));
    assert!(!page.contains("Подписка") && !page.contains("Копировать"));
    assert!(!page.contains("Данные для ручной настройки"));
}

#[test]
fn a_hostile_uri_artifact_gets_no_link_only_copyable_text() {
    let (manifest, mut artifacts) = fixture();
    for hostile in ["javascript:alert(1)", "tg://x\" onmouseover=\"alert(1)", "data:text/html,<b>x</b>"] {
        for artifact in artifacts.get_mut("g-mt").unwrap() {
            artifact.value = hostile.into();
        }
        let options = RenderOptions { url: "https://sub.example.com/s/TOKEN".into(), ..RenderOptions::default() };
        let page = text(Format::Html, &manifest, &artifacts, &options);
        assert!(!page.contains(&format!("href=\"{hostile}")));
        assert!(!page.contains("href=\"javascript:") && !page.contains("href=\"data:text"));
        assert!(!page.contains("onmouseover=\"alert"));
    }
}
