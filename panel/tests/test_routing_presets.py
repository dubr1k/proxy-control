"""Quick settings and the sniffed-protocol selector (v0.8): a preset is a rule with a mark
that the store keeps, the router compiles `protocols` into Xray's `protocol` and the
native backends refuse it honestly, the definitions come from one place."""
from __future__ import annotations




import pytest








from panel.routing.presets import PRESET_IDS


pytestmark = pytest.mark.anyio


















# The router's side of the protocol selector (the intent keeps `protocols`, the Xray rule carries
# `protocol`) is tested with the Rust manager:
# xray_router_manager/src/intent.rs::the_router_intent_and_the_xray_rule_carry_the_protocol_selector.






async def test_the_presets_endpoint_lists_the_definitions(client, login_user):
    await login_user(client)
    response = await client.get("/api/routing/presets")
    assert response.status_code == 200
    items = response.json()["items"]
    assert [item["id"] for item in items] == list(PRESET_IDS)
    assert items[0]["rule"]["match"] == {"protocols": ["bittorrent"]} and items[0]["placement"] == "first"






