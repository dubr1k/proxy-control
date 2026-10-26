//! Quick settings (v0.8, «Быстрые настройки», `routing/presets.py`): the toggles 3x-ui's «Basic
//! Routing» offers, as ordinary rules of the policy carrying a `preset` mark.
//!
//! v1.0.1: regional settings; `geodata` names the source a preset needs.

use serde_json::{json, Map, Value};

/// `PRESETS`, in their order (what `GET /api/routing/presets` lists).
pub fn presets() -> Vec<Value> {
    vec![
        json!({"id": "torrent", "title": "Торренты → блок", "placement": "first",
               "description": "Соединения, которые сниффер Xray опознал как BitTorrent, блокируются (только на Xray-router).",
               "rule": {"action": "block", "match": {"protocols": ["bittorrent"]}, "note": "Торренты → блок"}}),
        json!({"id": "ads", "title": "Реклама → блок", "placement": "first",
               "description": "Домены рекламы и трекеров из geosite:category-ads-all блокируются.",
               "rule": {"action": "block", "match": {"geosites": ["category-ads-all"]}, "note": "Реклама → блок"}}),
        json!({"id": "ru_direct", "title": "Российские домены и IP → напрямую", "placement": "last",
               "description": "geosite:category-ru и geoip:ru идут напрямую, минуя выход по умолчанию.",
               "rule": {"action": "direct", "match": {"geosites": ["category-ru"], "geoips": ["ru"]}, "note": "RU → напрямую"}}),
        json!({"id": "ru_blocked_warp", "title": "Заблокированное в РФ → через WARP", "placement": "last", "geodata": "runetfreedom",
               "description": "geosite:ru-blocked и geoip:ru-blocked уходят через WARP узла, остальное — как по умолчанию. Нужен источник geodata «Россия — runetfreedom».",
               "rule": {"action": "egress", "egress": "warp", "match": {"geosites": ["ru-blocked"], "geoips": ["ru-blocked"]},
                        "note": "Заблокированное в РФ → WARP"}}),
        json!({"id": "cn_direct", "title": "Китайские домены и IP → напрямую", "placement": "last",
               "description": "geosite:cn и geoip:cn идут напрямую, минуя выход по умолчанию.",
               "rule": {"action": "direct", "match": {"geosites": ["cn"], "geoips": ["cn"]}, "note": "CN → напрямую"}}),
        json!({"id": "ir_direct", "title": "Иранские домены и IP → напрямую", "placement": "last",
               "description": "geosite:category-ir и geoip:ir идут напрямую, минуя выход по умолчанию.",
               "rule": {"action": "direct", "match": {"geosites": ["category-ir"], "geoips": ["ir"]}, "note": "IR → напрямую"}}),
    ]
}

/// `PRESET_IDS`.
pub fn preset_ids() -> Vec<String> {
    presets().iter().filter_map(|item| item["id"].as_str().map(str::to_string)).collect()
}

/// `preset(preset_id)`.
pub fn preset(preset_id: &str) -> Option<Value> {
    presets().into_iter().find(|item| item["id"] == preset_id)
}

/// `rule_for(preset_id)`: the rule a toggle adds, with its mark (`None` for an unknown id,
/// Python's `KeyError`).
pub fn rule_for(preset_id: &str) -> Option<Value> {
    let found = preset(preset_id)?;
    let mut rule = Map::new();
    rule.insert("enabled".into(), json!(true));
    rule.insert("egress".into(), Value::Null);
    rule.insert("preset".into(), json!(preset_id));
    if let Some(defined) = found["rule"].as_object() {
        for (key, value) in defined {
            rule.insert(key.clone(), value.clone());
        }
    }
    Some(Value::Object(rule))
}

#[cfg(test)]
mod tests {
    use super::*;
    use panel_model::routing::models::{Action, RoutingRule};
    use panel_model::validate::Model;

    #[test]
    fn every_preset_is_a_valid_rule_and_the_ids_are_distinct() {
        let ids = preset_ids();
        let mut distinct = ids.clone();
        distinct.sort();
        distinct.dedup();
        assert_eq!((distinct.len(), ids.len()), (6, 6));
        for item in presets() {
            let id = item["id"].as_str().unwrap();
            let rule = RoutingRule::validate(&rule_for(id).unwrap()).unwrap();
            assert_eq!(rule.preset.as_deref(), Some(id));
            assert!(["first", "last"].contains(&item["placement"].as_str().unwrap()));
        }
        assert!(rule_for("nope").is_none());
    }

    #[test]
    fn a_rule_may_stand_on_the_sniffed_protocol_alone_and_carries_its_preset() {
        let rule = RoutingRule::validate(&rule_for("torrent").unwrap()).unwrap();
        assert_eq!(rule.matcher.protocols, ["bittorrent"]);
        assert_eq!((rule.preset.as_deref(), rule.action), (Some("torrent"), Action::Block));
    }

    #[test]
    fn regional_presets_name_the_geodata_source_their_codes_need() {
        let blocked = RoutingRule::validate(&rule_for("ru_blocked_warp").unwrap()).unwrap();
        assert_eq!((blocked.action, blocked.egress.as_deref()), (Action::Egress, Some("warp")));
        assert_eq!(blocked.matcher.geosites, ["ru-blocked"]);
        assert_eq!(blocked.matcher.geoips, ["ru-blocked"]);
        assert_eq!(preset("ru_blocked_warp").unwrap()["geodata"], "runetfreedom");
        assert!(preset("cn_direct").unwrap().get("geodata").is_none());
        assert!(preset("ir_direct").unwrap().get("geodata").is_none());
        assert_eq!(RoutingRule::validate(&rule_for("cn_direct").unwrap()).unwrap().matcher.geoips, ["cn"]);
        assert_eq!(RoutingRule::validate(&rule_for("ir_direct").unwrap()).unwrap().matcher.geosites, ["category-ir"]);
    }
}
