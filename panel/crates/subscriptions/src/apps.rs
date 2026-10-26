//! «На чём клиент?» — the one catalogue of apps that take the subscription link
//! (`subscriptions/apps.py`).
//!
//! An app maps to exactly one link variant (a key of [`SHARE_VARIANTS`]) and to one column of the
//! compatibility matrix. What the app gets is derived: `works` when the variant delivers the
//! protocol and the cell is `supported`, `unverified` when delivered but not proven, `pending` when
//! the feed carries it but the app's releases do not support it yet, `no` otherwise. `deeplink` is
//! the template of the «Открыть в приложении» button (a scheme only where the vendor's own docs or
//! source state it), or `None`.

use panel_core::pytext;
use serde_json::{json, Map, Value};

use crate::compatibility;
use crate::text::is_deep_link;

/// The protocols a subscription carries (MTProxy and AmneziaWG are not subscription protocols).
pub const SUBSCRIPTION_PROTOCOLS: [&str; 3] = ["naive", "mieru", "trusttunnel"];

/// The link variants an operator can hand out: a format and (for the sing-box JSON) the client
/// it is cut for, in Python's order.
pub const SHARE_VARIANTS: [(&str, &str); 6] = [
    ("raw", "?format=raw"),
    ("singbox", "?format=singbox"),
    ("singbox-official", "?format=singbox&client=singbox"),
    // The fork cores that carry a TrustTunnel outbound (hiddify-sing-box, the NekoBox fork).
    ("singbox-hiddify", "?format=singbox&client=hiddify"),
    ("singbox-nekobox", "?format=singbox&client=nekobox"),
    ("clash", "?format=clash"),
];

/// `SHARE_VARIANTS[name]`.
pub fn share_variant(name: &str) -> Option<&'static str> {
    SHARE_VARIANTS.iter().find(|(key, _)| *key == name).map(|(_, query)| *query)
}

/// `PLATFORMS`.
pub const PLATFORMS: [(&str, &str); 5] =
    [("ios", "iPhone / iPad"), ("android", "Android"), ("windows", "Windows"), ("macos", "macOS"), ("linux", "Linux")];

/// `STATUSES`.
pub const STATUSES: [&str; 4] = ["works", "unverified", "pending", "no"];

/// One app of the catalogue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct App {
    pub id: &'static str,
    pub name: &'static str,
    pub variant: &'static str,
    pub matrix: &'static str,
    pub platforms: &'static [&'static str],
    pub delivers: &'static [&'static str],
    pub pending: &'static [&'static str],
    pub summary: &'static str,
    pub deeplink: Option<&'static str>,
    pub downloads: &'static [(&'static str, &'static str)],
}

/// `APPS`, in order.
pub const APPS: [App; 7] = [
    App {
        id: "karing",
        name: "Karing",
        variant: "singbox",
        matrix: "karing",
        platforms: &["ios", "android", "windows", "macos", "linux"],
        delivers: &["naive", "mieru"],
        pending: &[],
        summary: "Бесплатное приложение, само подтягивает изменения по ссылке.",
        // https://karing.app/en/cooperation/scheme — karing://install-config?url=xxxx&name=xxx
        deeplink: Some("karing://install-config?url={url_enc}&name={name_enc}"),
        downloads: &[
            ("Сайт приложения", "https://karing.app/"),
            ("Выпуски на GitHub", "https://github.com/KaringX/karing/releases"),
        ],
    },
    App {
        id: "hiddify",
        name: "Hiddify",
        variant: "singbox-hiddify",
        matrix: "hiddify",
        platforms: &["ios", "android", "windows", "macos", "linux"],
        delivers: &["trusttunnel"],
        // TrustTunnel is not in Hiddify's app releases yet; the link is ready for when it is.
        pending: &["trusttunnel"],
        summary: "Бесплатное приложение; ссылка для TrustTunnel готова, но в выпусках приложения его пока нет.",
        // https://hiddify.com/app/URL-Scheme/ — hiddify://import/<sublink>#name
        deeplink: Some("hiddify://import/{url}#{name_enc}"),
        downloads: &[
            ("Сайт приложения", "https://hiddify.com/app/"),
            ("Выпуски на GitHub", "https://github.com/hiddify/hiddify-app/releases"),
        ],
    },
    App {
        id: "singbox",
        name: "sing-box",
        variant: "singbox-official",
        matrix: "singbox",
        platforms: &["ios", "android", "macos"],
        delivers: &["naive"],
        pending: &[],
        summary: "Официальное приложение sing-box; подойдёт, если нужен только NaiveProxy.",
        // https://sing-box.sagernet.org/clients/general/ — sing-box://import-remote-profile?url=urlEncodedURL#urlEncodedName
        deeplink: Some("sing-box://import-remote-profile?url={url_enc}#{name_enc}"),
        downloads: &[("Где скачать", "https://sing-box.sagernet.org/clients/general/")],
    },
    App {
        id: "throne",
        name: "Throne",
        variant: "singbox",
        matrix: "throne",
        platforms: &["windows", "macos", "linux", "android"],
        delivers: &["naive", "mieru", "trusttunnel"],
        pending: &[],
        summary: "Бесплатное приложение для компьютера.",
        // No deep link: Throne has none yet (throneproj/Throne#1179, closed as a duplicate of #855).
        deeplink: None,
        downloads: &[
            ("Сайт приложения", "https://throneproj.github.io/"),
            ("Выпуски на GitHub", "https://github.com/throneproj/Throne/releases"),
        ],
    },
    App {
        id: "flclash",
        name: "FlClash",
        variant: "clash",
        matrix: "mihomo",
        platforms: &["android", "windows", "macos", "linux"],
        delivers: &["mieru", "trusttunnel"],
        pending: &[],
        summary: "Бесплатное приложение на ядре mihomo (Clash Meta).",
        // https://github.com/chen08209/FlClash (README, Usage) — clash://install-config?url=<URL-encoded subscription link>
        deeplink: Some("clash://install-config?url={url_enc}"),
        downloads: &[("Выпуски на GitHub", "https://github.com/chen08209/FlClash/releases")],
    },
    App {
        id: "clash-verge-rev",
        name: "Clash Verge Rev",
        variant: "clash",
        matrix: "mihomo",
        platforms: &["windows", "macos", "linux"],
        delivers: &["mieru", "trusttunnel"],
        pending: &[],
        summary: "Бесплатное приложение на ядре mihomo (Clash Meta).",
        // No deep link: its import scheme is not stated in any doc we could check.
        deeplink: None,
        downloads: &[("Выпуски на GitHub", "https://github.com/clash-verge-rev/clash-verge-rev/releases")],
    },
    App {
        id: "clashmi",
        name: "Clash Mi",
        variant: "clash",
        matrix: "mihomo",
        platforms: &["ios", "android", "windows", "macos", "linux"],
        delivers: &["mieru", "trusttunnel"],
        pending: &[],
        summary: "Бесплатное приложение на ядре mihomo (Clash Meta).",
        // No deep link: the scheme is not stated in the docs we could check (KaringX/clashmi-docu).
        deeplink: None,
        downloads: &[("Выпуски на GitHub", "https://github.com/KaringX/clashmi/releases")],
    },
];

/// `protocol_status(app, protocol)`: works / unverified / pending / no.
pub fn protocol_status(app: &App, protocol: &str) -> &'static str {
    if !app.delivers.contains(&protocol) {
        return "no";
    }
    if app.pending.contains(&protocol) {
        return "pending";
    }
    match compatibility::status(protocol, app.matrix) {
        Some("supported") => "works",
        Some("unproven") => "unverified",
        _ => "no",
    }
}

/// `catalogue()`: the JSON the panel UI renders the chooser from.
pub fn catalogue() -> Map<String, Value> {
    let platforms: Vec<Value> = PLATFORMS.iter().map(|(id, name)| json!({"id": id, "name": name})).collect();
    let apps: Vec<Value> = APPS
        .iter()
        .map(|app| {
            let protocols: Map<String, Value> = SUBSCRIPTION_PROTOCOLS
                .iter()
                .map(|protocol| (protocol.to_string(), Value::from(protocol_status(app, protocol))))
                .collect();
            json!({
                "id": app.id,
                "name": app.name,
                "summary": app.summary,
                "platforms": app.platforms,
                "variant": app.variant,
                "protocols": protocols,
                "deeplink": app.deeplink,
                "downloads": app.downloads.iter().map(|(label, url)| json!({"label": label, "url": url})).collect::<Vec<_>>(),
            })
        })
        .collect();
    let mut out = Map::new();
    out.insert("platforms".into(), Value::Array(platforms));
    out.insert("apps".into(), Value::Array(apps));
    out
}

/// `deep_link(app, url, name)`: the «open in the app» link for one subscription link, or `""` when
/// the app has none or the guard refuses the result. `quote(…, safe="")` also encodes `!'()*`.
pub fn deep_link(app: &App, url: &str, name: &str) -> String {
    let Some(template) = app.deeplink else { return String::new() };
    let href = template
        .replace("{url_enc}", &pytext::quote(url, ""))
        .replace("{name_enc}", &pytext::quote(name, ""))
        .replace("{url}", url);
    if is_deep_link(&href) {
        href
    } else {
        String::new()
    }
}

/// One app worth offering, with the protocols that work / are unverified / pending / not there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppEntry {
    pub app: &'static App,
    pub order: usize,
    pub works: Vec<String>,
    pub unverified: Vec<String>,
    pub pending: Vec<String>,
    pub no: Vec<String>,
}

/// `apps_for(protocols)`: the apps worth offering, best first — most proven protocols first, ties to
/// the one that loses less, then catalogue order. An app that would take none is left out.
pub fn apps_for(protocols: &[String]) -> Vec<AppEntry> {
    let mut entries: Vec<AppEntry> = Vec::new();
    for (order, app) in APPS.iter().enumerate() {
        let of = |status: &str| -> Vec<String> {
            protocols.iter().filter(|protocol| protocol_status(app, protocol) == status).cloned().collect()
        };
        let entry = AppEntry {
            app,
            order,
            works: of("works"),
            unverified: of("unverified"),
            pending: of("pending"),
            no: of("no"),
        };
        if !entry.works.is_empty() || !entry.unverified.is_empty() {
            entries.push(entry);
        }
    }
    entries
        .sort_by_key(|entry| (std::cmp::Reverse(entry.works.len()), entry.no.len() + entry.pending.len(), entry.order));
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    fn by_id(id: &str) -> Value {
        catalogue()["apps"].as_array().unwrap().iter().find(|app| app["id"] == id).unwrap().clone()
    }

    #[test]
    fn every_app_maps_to_one_existing_link_variant_and_matrix_column() {
        for app in &APPS {
            assert!(share_variant(app.variant).is_some(), "{}", app.id);
            assert!(compatibility::status("naive", app.matrix).is_some(), "{}", app.id);
            assert!(app.delivers.iter().all(|protocol| SUBSCRIPTION_PROTOCOLS.contains(protocol)), "{}", app.id);
            assert!(app.platforms.iter().all(|platform| PLATFORMS.iter().any(|(key, _)| key == platform)));
        }
        let ids: std::collections::BTreeSet<&str> = APPS.iter().map(|app| app.id).collect();
        assert_eq!(ids.len(), APPS.len());
    }

    #[test]
    fn what_an_app_gets_is_derived_from_the_matrix_and_the_variant() {
        assert_eq!(by_id("karing")["protocols"], json!({"naive": "works", "mieru": "works", "trusttunnel": "no"}));
        assert_eq!(by_id("hiddify")["protocols"], json!({"naive": "no", "mieru": "no", "trusttunnel": "pending"}));
        assert_eq!(by_id("singbox")["protocols"], json!({"naive": "works", "mieru": "no", "trusttunnel": "no"}));
        assert_eq!(by_id("flclash")["protocols"], json!({"naive": "no", "mieru": "works", "trusttunnel": "works"}));
        assert_eq!(by_id("throne")["protocols"]["trusttunnel"], "unverified");
    }

    #[test]
    fn deep_links_use_known_schemes() {
        for app in &APPS {
            let Some(template) = app.deeplink else { continue };
            let scheme = template.split("://").next().unwrap();
            assert!(["karing", "hiddify", "sing-box", "clash"].contains(&scheme), "{}", app.id);
            assert!(template.contains("{url"), "{}", app.id);
        }
        assert_eq!(by_id("throne")["deeplink"], Value::Null);
        assert_eq!(by_id("clash-verge-rev")["deeplink"], Value::Null);
        assert_eq!(by_id("clashmi")["deeplink"], Value::Null);
        assert_eq!(by_id("hiddify")["deeplink"], "hiddify://import/{url}#{name_enc}");
    }

    #[test]
    fn download_links_are_https() {
        for app in catalogue()["apps"].as_array().unwrap() {
            let downloads = app["downloads"].as_array().unwrap();
            assert!(!downloads.is_empty());
            assert!(downloads.iter().all(|item| item["url"].as_str().unwrap().starts_with("https://")
                && !item["label"].as_str().unwrap().is_empty()));
        }
    }

    #[test]
    fn a_deep_link_is_built_from_the_quoted_url_and_name() {
        let karing = &APPS[0];
        assert_eq!(
            deep_link(karing, "https://sub.example.com/s/T?format=singbox", "O'Brien \"x\""),
            "karing://install-config?url=https%3A%2F%2Fsub.example.com%2Fs%2FT%3Fformat%3Dsingbox&name=O%27Brien%20%22x%22"
        );
        assert_eq!(deep_link(&APPS[3], "https://x", "n"), "");
        assert_eq!(deep_link(&APPS[1], "https://x y", "n"), "");
    }
}
