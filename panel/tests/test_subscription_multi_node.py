"""A subscription renders every grant of a client, each with its own node's public host."""
from urllib.parse import urlsplit

import pytest

pytestmark = pytest.mark.anyio

SUB_HOST = "sub.example"


async def test_subscription_lists_grants_of_every_node_with_node_public_hosts(pair_factory, login_user):
    node, central, plaintext = pair_factory(central={"hosts": ("testserver", "central.example", SUB_HOST),
                                                     "subscription_url": f"https://{SUB_HOST}"})
    central.create_admin("owner", "correct horse battery staple")
    async with central.http() as http:
        await login_user(http)
        http.headers["X-CSRF-Token"] = http.cookies["panel_csrf"]
        linked = await http.post("/api/nodes/link", json={"display_name": "Edge", "url": "https://node.example",
                                                          "api_key": plaintext, "tls_verify": "verify",
                                                          "allow_private_address": False})
        assert linked.status_code == 201, linked.text
        node_id = linked.json()["node_id"]
        created = (await http.post("/api/clients", json={"display_name": "A"})).json()
        grants = [{"protocol": "naive", "node_id": node_id_, "runtime_username": "same-user"}
                  for node_id_ in ("local", node_id)]
        started = await http.post(f"/api/clients/{created['id']}/grants", json={"grants": grants})
        # the local step is applied at once; the node's by the pusher
        assert started.status_code == 200 and started.json()["status"] == "pending_remote", started.text
        await central.tick("pusher")
        url = (await http.get(f"/api/reveal/{created['subscription_reveal_token']}")).json()["url"]
    token = urlsplit(url).path.rsplit("/", 1)[1]
    async with central.http(SUB_HOST) as public:
        raw = (await public.get(f"/s/{token}", params={"format": "raw"})).text.splitlines()
        outbounds = (await public.get(f"/s/{token}", params={"format": "singbox"})).json()["outbounds"]
    assert sorted(urlsplit(line).hostname for line in raw) == ["central.example", "node.example"]
    assert len({out["tag"] for out in outbounds}) == 2
    assert next(out for out in outbounds if out["server"] == "node.example")["tag"] == "Edge · Naive"
