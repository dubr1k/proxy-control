"""Quick settings (v0.8, «Быстрые настройки»): the toggles 3x-ui's «Basic Routing» offers,
as ordinary rules of the policy carrying a `preset` mark — nothing else in the model.

A toggle on adds the preset's rule (blocks go first, directions last); a toggle off removes
the rule with that mark; a rule the operator edits loses the mark (the UI clears it), so the
toggle honestly shows «off» for a rule that no longer is the preset. The codes are what the
Loyalsoldier lists and the Xray archive both carry; the router's preview still says
`geosite_unknown` if a node's lists lack one.
"""
from __future__ import annotations

PRESETS: tuple[dict, ...] = (
    {"id": "torrent", "title": "Торренты → блок", "placement": "first",
     "description": "Соединения, которые сниффер Xray опознал как BitTorrent, блокируются (только на Xray-router).",
     "rule": {"action": "block", "match": {"protocols": ["bittorrent"]}, "note": "Торренты → блок"}},
    {"id": "ads", "title": "Реклама → блок", "placement": "first",
     "description": "Домены рекламы и трекеров из geosite:category-ads-all блокируются.",
     "rule": {"action": "block", "match": {"geosites": ["category-ads-all"]}, "note": "Реклама → блок"}},
    {"id": "ru_direct", "title": "Российские домены и IP → напрямую", "placement": "last",
     "description": "geosite:category-ru и geoip:ru идут напрямую, минуя выход по умолчанию.",
     "rule": {"action": "direct", "match": {"geosites": ["category-ru"], "geoips": ["ru"]}, "note": "RU → напрямую"}},
)
PRESET_IDS = tuple(item["id"] for item in PRESETS)


def preset(preset_id: str) -> dict | None:
    return next((item for item in PRESETS if item["id"] == preset_id), None)


def rule_for(preset_id: str) -> dict:
    """The rule a toggle adds, with its mark; a copy the caller may own."""
    found = preset(preset_id)
    if found is None:
        raise KeyError(preset_id)
    return {"enabled": True, "egress": None, "preset": preset_id, **{k: (dict(v) if isinstance(v, dict) else v) for k, v in found["rule"].items()}}
