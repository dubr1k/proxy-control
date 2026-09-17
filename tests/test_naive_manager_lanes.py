"""The naive-manager's lanes (v0.7, spike S1): one `forward_proxy` handler per grant lane
inside the managed LANES block, each with its users and its own upstream — the router
ingress account of that lane — and the service's own handler last with everyone else."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from naive_manager.egress import EgressInvalid, parse
from naive_manager.lanes import LANES_BEGIN, LANES_END, LanesInvalid, lanes_span
from naive_manager.service import BEGIN, END, ManagerConflict, NaiveCredentialManager
from tests.test_naive_manager import manager as _manager
from tests.test_naive_manager_egress import ROUTER, ROUTER_SECRET, WARP, EgressHooks

ROUTER_DOC = {"schema": 1, "upstream": {"provider": "router"}, "acl": []}
LANE_A = {"lane": "grant:7f3a", "users": ["old-user"], "upstream": {"user": "grant-7f3a", "password": "A" * 43}}
LANE_B = {"lane": "grant:b2c4", "users": ["second"], "upstream": {"user": "grant-b2c4", "password": "B" * 43}}


class LaneHooks(EgressHooks):
    """The Caddy adapter's view of a Caddyfile with several `forward_proxy` handlers: one
    handler per directive, in order, with that handler's credentials and upstream."""

    def validate(self, path: Path):
        text = path.read_text()
        self.validated.append(text)
        if self.adapted_config is not None:
            return self.adapted_config
        handlers = []
        for block in re.findall(r"forward_proxy \{(.*?)\n\s*\}", text, re.DOTALL):
            handler = {"handler": "forward_proxy",
                       "auth_credentials": ["opaque"] * len(re.findall(r"^\s*basic_auth\s+\S+\s+\S+\s*$", block, re.MULTILINE))}
            upstream = re.search(r"^\s*upstream\s+(\S+)", block, re.MULTILINE)
            if upstream:
                handler["upstream"] = upstream.group(1)
            deny = re.findall(r"^\s*deny\s+(.+?)\s*$", block, re.MULTILINE)
            if deny:
                handler["acl"] = [{"subjects": [item for line in deny for item in line.split()]}]
            if self.readback_override is not None:
                handler.update(self.readback_override)
            handlers.append(handler)
        return {"apps": {"http": {"routes": [{"handle": handlers}]}}}


def lane_manager(tmp_path: Path, hooks: LaneHooks, *, router: str | None = ROUTER) -> NaiveCredentialManager:
    credential = tmp_path / "xray-router-ingress"
    credential.write_text(ROUTER_SECRET + "\n")
    instance = _manager(tmp_path, hooks)
    instance.provider_url = WARP
    instance.router_url = router
    instance.router_credential_file = credential if router else None
    instance.reachability = lambda url, timeout=3.0, auth=False: hooks.reachable
    instance.bootstrap()
    return instance


def _lanes_block(text: str) -> list[str]:
    lines = text.splitlines()
    span = lanes_span(lines)
    assert span is not None
    return lines[span[0]:span[1] + 1]


def test_set_lanes_renders_one_handler_per_lane_before_the_service_handler(tmp_path):
    hooks = LaneHooks()
    instance = lane_manager(tmp_path, hooks)
    reloads = hooks.reloads
    view = instance.set_lanes({"lanes": [LANE_A]})
    text = hooks.caddyfile.read_text()
    block = _lanes_block(text)
    assert block[0].strip() == LANES_BEGIN and block[-1].strip() == LANES_END
    body = "\n".join(block)
    assert "basic_auth old-user old-password" in body
    assert f"upstream socks5://grant-7f3a:{'A' * 43}@127.0.0.1:45101" in body
    assert "hide_ip" in body and "hide_via" in body and "probe_resistance" in body
    # the lanes block sits inside `route {` before the service's forward_proxy; the user left the USERS block
    lines = text.splitlines()
    route = next(i for i, line in enumerate(lines) if re.match(r"^\s*route\s*\{", line))
    span = lanes_span(lines)
    service = max(i for i, line in enumerate(lines) if re.match(r"^\s*forward_proxy\s*\{", line))
    assert route < span[0] < span[1] < service
    users = lines[next(i for i, line in enumerate(lines) if line.strip() == BEGIN) + 1:next(i for i, line in enumerate(lines) if line.strip() == END)]
    assert [line.split()[1] for line in users] == ["second"]
    assert hooks.reloads == reloads + 1 and hooks.probes >= 1
    # the view names lanes and users, masks the upstream, and the state remembers the lane
    assert view == {"lanes": [{"lane": "grant:7f3a", "users": ["old-user"], "upstream": "socks5://***@127.0.0.1:45101", "enabled_users": 1}]}
    assert "A" * 43 not in json.dumps(view)
    state = json.loads(instance.state_file.read_text())
    assert next(row for row in state["users"] if row["username"] == "old-user")["lane"] == "grant:7f3a"
    assert "A" * 43 in instance.state_file.read_text()
    assert [row["lane"] for row in instance.list_users()] == ["grant:7f3a", None]
    # the service's own egress and users are untouched
    assert parse(text).mode == "custom"
    assert instance.egress()["mode"] == "custom"


def test_lanes_replace_move_and_empty_out(tmp_path):
    hooks = LaneHooks()
    instance = lane_manager(tmp_path, hooks)
    instance.set_lanes({"lanes": [LANE_A, LANE_B]})
    text = hooks.caddyfile.read_text()
    assert text.count("forward_proxy {") == 3
    assert "\n".join(_lanes_block(text)).index("grant-7f3a") < "\n".join(_lanes_block(text)).index("grant-b2c4")
    # moving a user between lanes, dropping a lane
    moved = {"lane": "grant:b2c4", "users": ["old-user", "second"], "upstream": LANE_B["upstream"]}
    instance.set_lanes({"lanes": [moved]})
    text = hooks.caddyfile.read_text()
    assert text.count("forward_proxy {") == 2 and "grant-7f3a" not in text
    users_block = "\n".join(_lanes_block(text))
    assert "basic_auth old-user" in users_block and "basic_auth second" in users_block
    assert instance.lanes() == {"lanes": [{"lane": "grant:b2c4", "users": ["old-user", "second"],
                                          "upstream": "socks5://***@127.0.0.1:45101", "enabled_users": 2}]}
    # no lanes at all: the block disappears, everybody is back in the USERS block
    instance.set_lanes({"lanes": []})
    text = hooks.caddyfile.read_text()
    assert LANES_BEGIN not in text and text.count("forward_proxy {") == 1
    assert [row["lane"] for row in instance.list_users()] == [None, None]
    assert instance.lanes() == {"lanes": []}


def test_disabled_users_stay_out_of_the_lane_handler_but_keep_their_lane(tmp_path):
    hooks = LaneHooks()
    instance = lane_manager(tmp_path, hooks)
    instance.set_lanes({"lanes": [LANE_A]})
    instance.set_enabled("old-user", False)
    text = hooks.caddyfile.read_text()
    assert LANES_BEGIN not in text  # a lane with no enabled user renders no handler
    assert instance.lanes()["lanes"][0]["enabled_users"] == 0
    instance.set_enabled("old-user", True)
    assert "basic_auth old-user" in "\n".join(_lanes_block(hooks.caddyfile.read_text()))
    # a rotated password lands in the lane handler, not in the USERS block
    instance.rotate("old-user")
    text = hooks.caddyfile.read_text()
    new_password = next(row["password"] for row in json.loads(instance.state_file.read_text())["users"] if row["username"] == "old-user")
    assert f"basic_auth old-user {new_password}" in "\n".join(_lanes_block(text))
    # taking the user out of the lane (a lanes request without them) removes the handler
    instance.set_lanes({"lanes": []})
    assert LANES_BEGIN not in hooks.caddyfile.read_text()


@pytest.mark.parametrize("body", [
    {"lanes": [{"lane": "svc:naive", "users": ["old-user"], "upstream": LANE_A["upstream"]}]},
    {"lanes": [{"lane": "grant:7f3a", "users": ["nobody"], "upstream": LANE_A["upstream"]}]},
    {"lanes": [LANE_A, {"lane": "grant:x", "users": ["old-user"], "upstream": LANE_B["upstream"]}]},
    {"lanes": [{"lane": "grant:7f3a", "users": [], "upstream": LANE_A["upstream"]}]},
    {"lanes": [{"lane": "grant:7f3a", "users": ["old-user"], "upstream": {"user": "grant-7f3a"}}]},
    {"lanes": [{"lane": "grant:7f3a", "users": ["old-user"], "upstream": {"user": "bad user", "password": "A" * 43}}]},
    {"lanes": [{"lane": "grant:7f3a", "users": ["old-user"], "upstream": LANE_A["upstream"], "extra": 1}]},
    {"lanes": [LANE_A] * 2},
    {"lanes": "nope"},
    {},
])
def test_set_lanes_refuses_bad_requests_before_any_io(tmp_path, body):
    hooks = LaneHooks()
    instance = lane_manager(tmp_path, hooks)
    reloads = hooks.reloads
    with pytest.raises((LanesInvalid, ManagerConflict)):
        instance.set_lanes(body)
    assert hooks.reloads == reloads and LANES_BEGIN not in hooks.caddyfile.read_text()


def test_lanes_need_the_router_and_a_failed_reload_restores_everything(tmp_path):
    (tmp_path / "no-router").mkdir()
    without = lane_manager(tmp_path / "no-router", LaneHooks(), router=None)
    with pytest.raises(EgressInvalid, match="router"):
        without.set_lanes({"lanes": [LANE_A]})
    hooks = LaneHooks()
    instance = lane_manager(tmp_path, hooks)
    before = hooks.caddyfile.read_text()
    state_before = instance.state_file.read_text()
    hooks.fail_reload_calls = {hooks.reloads + 1}
    with pytest.raises(RuntimeError):
        instance.set_lanes({"lanes": [LANE_A]})
    assert hooks.caddyfile.read_text() == before and instance.state_file.read_text() == state_before
    assert instance.lanes() == {"lanes": []}


def test_a_lane_handler_changed_outside_the_manager_is_a_conflict(tmp_path):
    hooks = LaneHooks()
    instance = lane_manager(tmp_path, hooks)
    instance.set_lanes({"lanes": [LANE_A]})
    text = hooks.caddyfile.read_text().replace("basic_auth old-user old-password", "basic_auth old-user other")
    hooks.caddyfile.write_text(text)
    with pytest.raises(ManagerConflict, match="outside manager"):
        instance.set_enabled("second", False)


def test_egress_readback_and_bootstrap_keep_working_with_lanes(tmp_path):
    hooks = LaneHooks()
    instance = lane_manager(tmp_path, hooks)
    instance.set_lanes({"lanes": [LANE_A]})
    revision = instance.egress()["revision"]
    instance.egress_apply(revision, ROUTER_DOC, "op-router")
    text = hooks.caddyfile.read_text()
    assert text.count("forward_proxy {") == 2 and f"upstream socks5://naive-a1b2c3d4:{'K' * 40}@127.0.0.1:45101" in text
    assert instance.egress()["mode"] == "proxy"
    # a second manager over the same files (a restart) sees the same lanes and users
    again = _manager(tmp_path, LaneHooks())
    again.provider_url, again.router_url = WARP, ROUTER
    again.router_credential_file = tmp_path / "xray-router-ingress"
    again.bootstrap()
    assert again.lanes()["lanes"][0]["lane"] == "grant:7f3a" and [row["lane"] for row in again.list_users()] == ["grant:7f3a", None]


def test_unix_api_lanes_routes(tmp_path):
    import threading

    import httpx

    from naive_manager.server import ManagerHTTPServer

    hooks = LaneHooks()
    instance = lane_manager(tmp_path, hooks)
    socket_path = tmp_path / "manager.sock"
    server = ManagerHTTPServer(socket_path, instance, "internal-token")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        headers = {"X-Naive-Token": "internal-token"}
        with httpx.Client(transport=httpx.HTTPTransport(uds=str(socket_path)), base_url="http://manager") as client:
            assert client.get("/v1/lanes").status_code == 401
            assert client.get("/v1/lanes", headers=headers).json() == {"lanes": []}
            put = client.put("/v1/lanes", json={"lanes": [LANE_A]}, headers=headers)
            assert put.status_code == 200 and put.json()["lanes"][0]["users"] == ["old-user"]
            assert "A" * 43 not in put.text and put.json()["lanes"][0]["upstream"] == "socks5://***@127.0.0.1:45101"
            bad = client.put("/v1/lanes", json={"lanes": [{"lane": "svc:naive", "users": ["old-user"], "upstream": LANE_A["upstream"]}]}, headers=headers)
            assert (bad.status_code, bad.json()["code"]) == (409, "lanes_invalid")
            assert client.get("/v1/users", headers=headers).json()[0]["lane"] == "grant:7f3a"
            assert client.put("/v1/lanes", json={"lanes": []}, headers=headers).json() == {"lanes": []}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
