"""The naive-manager's egress API (v0.4): get / plan / apply / rollback over the managed
block, with the same transaction, readback and recovery discipline as the user block."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from naive_manager.egress import EGRESS_BEGIN, EGRESS_END, EgressInvalid, EgressUnreachable
from naive_manager.service import ManagerConflict, NaiveCredentialManager
from tests.test_naive_manager import Hooks, manager as _manager

WARP = "socks5://127.0.0.1:45000"
DIRECT_DOC = {"schema": 1, "upstream": None, "acl": []}
WARP_DOC = {"schema": 1, "upstream": {"provider": "warp"}, "acl": []}
BLOCK_DOC = {"schema": 1, "upstream": None, "acl": [{"deny": ["example.com", "*.example.com"]}]}


class EgressHooks(Hooks):
    """`validate` also mirrors what the Caddy adapter would report for the egress block, so
    the manager's readback sees what it wrote (or, when told to, something else)."""

    def __init__(self):
        super().__init__()
        self.reachable = True
        self.readback_override = None

    def validate(self, path: Path):
        from naive_manager.egress import parse

        text = path.read_text()
        self.validated.append(text)
        if self.adapted_config is not None:
            return self.adapted_config
        count = len(NaiveCredentialManager._managed_credentials(text))
        parsed = parse(text)
        handler = {"handler": "forward_proxy", "auth_credentials": ["opaque"] * count}
        if parsed.upstream:
            handler["upstream"] = parsed.upstream
        if parsed.acl_deny:
            handler["acl"] = [{"subjects": list(parsed.acl_deny)}]
        if self.readback_override is not None:
            handler.update(self.readback_override)
        return {"apps": {"http": handler}}


def manager(tmp_path: Path, hooks: EgressHooks, *, provider: str | None = WARP) -> NaiveCredentialManager:
    instance = _manager(tmp_path, hooks)
    instance.provider_url = provider
    instance.reachability = lambda url, timeout=3.0: hooks.reachable
    instance.bootstrap()
    return instance


def _block(text: str) -> list[str]:
    lines = text.splitlines()
    begin = next(i for i, line in enumerate(lines) if line.strip() == EGRESS_BEGIN)
    end = next(i for i, line in enumerate(lines) if line.strip() == EGRESS_END)
    return lines[begin:end + 1]


def test_get_reports_the_legacy_upstream_as_the_provider_when_it_matches(tmp_path):
    hooks = EgressHooks()
    instance = manager(tmp_path, hooks, provider="socks5://127.0.0.1:40000")
    view = instance.egress()
    # The test Caddyfile carries `upstream socks5://127.0.0.1:40000` outside any marker.
    assert (view["mode"], view["upstream"], view["managed"]) == ("proxy", "socks5://127.0.0.1:40000", False)
    assert view["document"] == WARP_DOC
    assert view["providers"] == {"warp": {"url": "socks5://127.0.0.1:40000", "reachable": True}}
    assert view["capabilities"] == ["whole_direct", "whole_warp", "block_domain", "block_cidr"]
    assert view["restart_required"] is False and view["previous"] is None
    assert len(view["revision"]) == 64


def test_get_reports_custom_when_the_upstream_is_not_the_provider(tmp_path):
    hooks = EgressHooks()
    instance = manager(tmp_path, hooks, provider=WARP)
    view = instance.egress()
    assert (view["mode"], view["document"]) == ("custom", None)
    assert view["warnings"] == ["adopts_unmanaged_upstream"]
    hooks.reachable = False
    assert manager(tmp_path, EgressHooks(), provider=None).egress()["providers"] == {}


def test_plan_is_read_only_and_reports_the_diff(tmp_path):
    hooks = EgressHooks()
    instance = manager(tmp_path, hooks)
    before = hooks.caddyfile.read_bytes()
    current = instance.egress()["revision"]
    plan = instance.egress_plan(current, WARP_DOC)
    assert hooks.caddyfile.read_bytes() == before and hooks.reloads == 0
    assert plan["revision"] == current and plan["target_revision"] != current
    assert any(f"upstream {WARP}" in line for line in plan["diff"]) and plan["restart_required"] is False
    assert plan["reachability"] == {"warp": True} and plan["warnings"] == ["adopts_unmanaged_upstream"]
    assert len(plan["rendered_sha256"]) == 64


def test_apply_writes_the_block_reloads_and_reads_back(tmp_path):
    hooks = EgressHooks()
    instance = manager(tmp_path, hooks)
    current = instance.egress()["revision"]
    result = instance.egress_apply(current, WARP_DOC, "routing:p1:1")
    text = hooks.caddyfile.read_text()
    assert _block(text) == [f"            {EGRESS_BEGIN}", f"            upstream {WARP}", f"            {EGRESS_END}"]
    assert "upstream socks5://127.0.0.1:40000" not in text
    assert hooks.reloads == 1 and hooks.probes >= 1
    assert result["revision"] != current and result["applied"] == WARP_DOC and len(result["readback_sha256"]) == 64
    view = instance.egress()
    assert (view["mode"], view["managed"], view["document"], view["revision"]) == ("proxy", True, WARP_DOC, result["revision"])
    assert view["previous"] is not None and view["previous"]["revision"] == current
    state = json.loads((tmp_path / "state" / "users.json").read_text())
    assert state["egress"]["current"]["operation_id"] == "routing:p1:1"
    assert state["egress"]["previous"]["raw_lines"] == ["            upstream socks5://127.0.0.1:40000"]


def test_apply_keeps_every_other_line_byte_for_byte(tmp_path):
    hooks = EgressHooks()
    instance = manager(tmp_path, hooks)
    before = hooks.caddyfile.read_text()
    instance.egress_apply(instance.egress()["revision"], BLOCK_DOC, "op-1")
    after = hooks.caddyfile.read_text()
    without_block = after.replace("\n".join(_block(after)) + "\n", "")
    assert without_block == before.replace("            upstream socks5://127.0.0.1:40000\n", "")
    # Users still work: the user block is untouched and a user change keeps the egress block.
    instance.create("carol")
    assert _block(hooks.caddyfile.read_text()) == _block(after)
    assert instance.egress()["document"] == BLOCK_DOC


def test_apply_conflicts_on_a_stale_revision_without_touching_anything(tmp_path):
    hooks = EgressHooks()
    instance = manager(tmp_path, hooks)
    before = hooks.caddyfile.read_bytes()
    with pytest.raises(ManagerConflict) as caught:
        instance.egress_apply("0" * 64, WARP_DOC, "op-1")
    assert caught.value.code == "egress_conflict"
    assert hooks.caddyfile.read_bytes() == before and hooks.reloads == 0


def test_apply_refuses_an_unreachable_provider_and_an_unconfigured_one(tmp_path):
    hooks = EgressHooks()
    hooks.reachable = False
    instance = manager(tmp_path, hooks)
    before = hooks.caddyfile.read_bytes()
    with pytest.raises(EgressUnreachable):
        instance.egress_apply(instance.egress()["revision"], WARP_DOC, "op-1")
    assert hooks.caddyfile.read_bytes() == before and hooks.reloads == 0
    # Direct never needs the provider.
    instance.egress_apply(instance.egress()["revision"], DIRECT_DOC, "op-2")
    (tmp_path / "other").mkdir()
    without = manager(tmp_path / "other", EgressHooks(), provider=None)
    with pytest.raises(EgressInvalid, match="not configured"):
        without.egress_apply(without.egress()["revision"], WARP_DOC, "op-3")


def test_apply_rejects_an_invalid_document_before_any_io(tmp_path):
    hooks = EgressHooks()
    instance = manager(tmp_path, hooks)
    with pytest.raises(EgressInvalid):
        instance.egress_apply(instance.egress()["revision"], {"schema": 1, "upstream": None, "acl": [{"deny": ["bad host"]}]}, "op")
    assert hooks.reloads == 0


def test_a_failed_reload_restores_the_previous_bytes(tmp_path):
    hooks = EgressHooks()
    hooks.fail_reload_calls = {1}
    instance = manager(tmp_path, hooks)
    before = hooks.caddyfile.read_bytes()
    state_before = (tmp_path / "state" / "users.json").read_bytes()
    with pytest.raises(RuntimeError, match="reload failed"):
        instance.egress_apply(instance.egress()["revision"], WARP_DOC, "op-1")
    assert hooks.caddyfile.read_bytes() == before
    assert (tmp_path / "state" / "users.json").read_bytes() == state_before
    assert instance.health()["ready"] is True


def test_a_readback_mismatch_rolls_back_with_its_own_code(tmp_path):
    hooks = EgressHooks()
    instance = manager(tmp_path, hooks)
    before = hooks.caddyfile.read_bytes()
    hooks.readback_override = {"upstream": "socks5://127.0.0.1:1"}
    with pytest.raises(ManagerConflict) as caught:
        instance.egress_apply(instance.egress()["revision"], WARP_DOC, "op-1")
    assert caught.value.code == "egress_readback_mismatch"
    hooks.readback_override = None
    assert hooks.caddyfile.read_bytes() == before and instance.health()["ready"] is True


def test_apply_is_idempotent_by_operation_id(tmp_path):
    hooks = EgressHooks()
    instance = manager(tmp_path, hooks)
    first = instance.egress_apply(instance.egress()["revision"], WARP_DOC, "op-1")
    again = instance.egress_apply(first["revision"], WARP_DOC, "op-1")
    assert again["revision"] == first["revision"] and again["replayed"] is True and hooks.reloads == 1
    with pytest.raises(ManagerConflict):
        instance.egress_apply(first["revision"], DIRECT_DOC, "op-1")  # same id, another document


def test_rollback_restores_the_previous_entry_and_then_the_adopted_lines(tmp_path):
    hooks = EgressHooks()
    instance = manager(tmp_path, hooks)
    original = hooks.caddyfile.read_text()
    first = instance.egress_apply(instance.egress()["revision"], WARP_DOC, "op-1")
    second = instance.egress_apply(first["revision"], BLOCK_DOC, "op-2")
    rolled = instance.egress_rollback(second["revision"])
    assert rolled["revision"] == first["revision"] and instance.egress()["document"] == WARP_DOC
    rolled = instance.egress_rollback(rolled["revision"])
    assert hooks.caddyfile.read_text() == original  # the adopted upstream line is back, byte for byte
    assert instance.egress()["mode"] == "custom" and instance.egress()["managed"] is False
    with pytest.raises(ManagerConflict) as caught:
        instance.egress_rollback(rolled["revision"])
    assert caught.value.code == "egress_no_previous"


def test_recovery_after_a_crash_between_write_and_reload(tmp_path):
    hooks = EgressHooks()
    instance = manager(tmp_path, hooks)
    before = hooks.caddyfile.read_bytes()

    def crash():
        raise KeyboardInterrupt

    instance.reload = crash
    with pytest.raises(KeyboardInterrupt):
        instance.egress_apply(instance.egress()["revision"], WARP_DOC, "op-1")
    # The rollback ran inside the failure path; a fresh manager finds no open transaction.
    fresh = manager(tmp_path, EgressHooks())
    assert hooks.caddyfile.read_bytes() == before and fresh.health()["ready"] is True


def _with_userinfo(hooks: EgressHooks, tmp_path: Path) -> NaiveCredentialManager:
    """A Caddyfile whose hand-written upstream carries a credential: the API must never echo it."""
    instance = manager(tmp_path, hooks)
    text = hooks.caddyfile.read_text().replace("upstream socks5://127.0.0.1:40000",
                                               "upstream socks5://alice:s3cret@127.0.0.1:1080")
    hooks.caddyfile.write_text(text)
    return instance


def test_egress_view_redacts_custom_upstream_userinfo(tmp_path):
    hooks = EgressHooks()
    instance = _with_userinfo(hooks, tmp_path)
    view = instance.egress()
    assert (view["mode"], view["document"]) == ("custom", None)
    assert view["upstream"] == "socks5://***@127.0.0.1:1080"
    assert "s3cret" not in json.dumps(view)


ROUTER = "socks5://127.0.0.1:45101"
ROUTER_DOC = {"schema": 1, "upstream": {"provider": "router"}, "acl": []}
ROUTER_SECRET = "naive-a1b2c3d4:" + "K" * 40


def router_manager(tmp_path: Path, hooks: EgressHooks, *, secret: str = ROUTER_SECRET) -> NaiveCredentialManager:
    """A manager that knows its router ingress and the file with its credential."""
    credential = tmp_path / "xray-router-ingress"
    credential.write_text(secret + "\n")
    instance = _manager(tmp_path, hooks)
    instance.provider_url = WARP
    instance.router_url = ROUTER
    instance.router_credential_file = credential
    hooks.greetings = []
    instance.reachability = lambda url, timeout=3.0, auth=False: (hooks.greetings.append((url, auth)), hooks.reachable)[1]
    instance.bootstrap()
    return instance


def test_block_lines_router_upstream_carries_credential_from_file(tmp_path):
    hooks = EgressHooks()
    instance = router_manager(tmp_path, hooks)
    result = instance.egress_apply(instance.egress()["revision"], ROUTER_DOC, "op-router")
    text = hooks.caddyfile.read_text()
    assert f"upstream socks5://naive-a1b2c3d4:{'K' * 40}@127.0.0.1:45101" in _block(text)[1]
    assert result["applied"] == ROUTER_DOC
    # The reachability probe offered the password method to the router, never a bare greeting.
    assert (ROUTER, True) in hooks.greetings
    view = instance.egress()
    assert (view["mode"], view["document"]) == ("proxy", ROUTER_DOC)
    assert view["providers"]["router"] == {"url": ROUTER, "reachable": True}
    assert view["providers"]["warp"]["url"] == WARP


def test_egress_views_never_contain_router_credential(tmp_path):
    hooks = EgressHooks()
    instance = router_manager(tmp_path, hooks)
    revision = instance.egress()["revision"]
    plan = instance.egress_plan(revision, ROUTER_DOC)
    instance.egress_apply(revision, ROUTER_DOC, "op-router")
    texts = [json.dumps(plan), json.dumps(instance.egress()),
             json.dumps(instance.egress_plan(instance.egress()["revision"], WARP_DOC))]
    for text in texts:
        assert "K" * 40 not in text and "naive-a1b2c3d4" not in text
    assert instance.egress()["upstream"] == "socks5://***@127.0.0.1:45101"
    assert plan["reachability"] == {"router": True}


def test_apply_router_without_router_env_is_unsupported(tmp_path):
    hooks = EgressHooks()
    instance = manager(tmp_path, hooks)
    with pytest.raises(EgressInvalid, match="router"):
        instance.egress_apply(instance.egress()["revision"], ROUTER_DOC, "op-1")
    assert "router" not in instance.egress()["providers"]


def test_apply_router_unreachable_refuses_without_changes(tmp_path):
    hooks = EgressHooks()
    instance = router_manager(tmp_path, hooks)
    hooks.reachable = False
    before = hooks.caddyfile.read_bytes()
    with pytest.raises(EgressUnreachable, match="router"):
        instance.egress_apply(instance.egress()["revision"], ROUTER_DOC, "op-1")
    assert hooks.caddyfile.read_bytes() == before


def test_bootstrap_rerenders_router_block_after_rotation(tmp_path):
    hooks = EgressHooks()
    instance = router_manager(tmp_path, hooks)
    applied = instance.egress_apply(instance.egress()["revision"], ROUTER_DOC, "op-router")
    previous_revision = instance.egress()["previous"]["revision"]
    (tmp_path / "xray-router-ingress").write_text("naive-a1b2c3d4:" + "Z" * 40 + "\n")
    assert instance.egress()["warnings"] == ["router_credential_stale"]
    reloads = hooks.reloads
    fresh = router_manager(tmp_path, EgressHooks(), secret="naive-a1b2c3d4:" + "Z" * 40)
    text = hooks.caddyfile.read_text()
    assert f"upstream socks5://naive-a1b2c3d4:{'Z' * 40}@127.0.0.1:45101" in _block(text)[1]
    assert "K" * 40 not in text
    view = fresh.egress()
    assert view["warnings"] == [] and view["document"] == ROUTER_DOC
    assert view["revision"] != applied["revision"] and view["previous"]["revision"] == previous_revision
    assert view["current"]["operation_id"] == "op-router"
    assert hooks.reloads == reloads  # the fresh manager's own hooks reloaded, not the old one's
    # And a rollback still walks back to the floor, the adopted line restored verbatim.
    fresh.egress_rollback(view["revision"])
    assert "upstream socks5://127.0.0.1:40000" in hooks.caddyfile.read_text()


def test_hand_written_router_line_with_a_credential_is_the_router_provider(tmp_path):
    hooks = EgressHooks()
    credential = tmp_path / "xray-router-ingress"
    credential.write_text(ROUTER_SECRET + "\n")
    instance = _manager(tmp_path, hooks)
    instance.router_url, instance.router_credential_file, instance.provider_url = ROUTER, credential, None
    instance.reachability = lambda url, timeout=3.0, auth=False: True
    hooks.caddyfile.write_text(hooks.caddyfile.read_text().replace(
        "upstream socks5://127.0.0.1:40000", "upstream socks5://naive-a1b2c3d4:" + "K" * 40 + "@127.0.0.1:45101"))
    instance.bootstrap()
    view = instance.egress()
    assert (view["mode"], view["document"], view["managed"]) == ("proxy", ROUTER_DOC, False)
    assert "K" * 40 not in json.dumps(view)


def test_egress_plan_diff_redacts_userinfo(tmp_path):
    hooks = EgressHooks()
    instance = _with_userinfo(hooks, tmp_path)
    plan = instance.egress_plan(instance.egress()["revision"], WARP_DOC)
    assert any("socks5://***@127.0.0.1:1080" in line for line in plan["diff"])
    assert "s3cret" not in json.dumps(plan)
    # The journal keeps the adopted line byte for byte: that is what a rollback restores.
    instance.egress_apply(instance.egress()["revision"], WARP_DOC, "op-redact")
    state = json.loads((tmp_path / "state" / "users.json").read_text())
    assert state["egress"]["previous"]["raw_lines"] == ["            upstream socks5://alice:s3cret@127.0.0.1:1080"]
    assert "s3cret" not in json.dumps(instance.egress())
    instance.egress_rollback(instance.egress()["revision"])
    assert "upstream socks5://alice:s3cret@127.0.0.1:1080" in hooks.caddyfile.read_text()


def test_bootstrap_adopts_the_installer_seed_after_rotation(tmp_path):
    """The installer seeds `egress = router` as a plain `upstream` line with the credential of
    the day (v0.5). After a rotation that line is stale and unmanaged: bootstrap adopts it as
    a managed block with the file's credential, the old line kept as the rollback floor."""
    hooks = EgressHooks()
    instance = router_manager(tmp_path, hooks)
    seeded = hooks.caddyfile.read_text().replace(
        "upstream socks5://127.0.0.1:40000", f"upstream socks5://naive-a1b2c3d4:{'K' * 40}@127.0.0.1:45101")
    hooks.caddyfile.write_text(seeded)
    view = instance.egress()
    assert view["mode"] == "proxy" and view["document"] == ROUTER_DOC and view["managed"] is False
    assert view["warnings"] == ["adopts_unmanaged_upstream"]
    (tmp_path / "xray-router-ingress").write_text("naive-a1b2c3d4:" + "Z" * 40 + "\n")
    assert instance.egress()["warnings"] == ["adopts_unmanaged_upstream", "router_credential_stale"]
    fresh = router_manager(tmp_path, EgressHooks(), secret="naive-a1b2c3d4:" + "Z" * 40)
    text = hooks.caddyfile.read_text()
    assert f"upstream socks5://naive-a1b2c3d4:{'Z' * 40}@127.0.0.1:45101" in _block(text)[1]
    assert "K" * 40 not in text
    view = fresh.egress()
    assert view["managed"] is True and view["warnings"] == [] and view["document"] == ROUTER_DOC
    assert view["previous"] is not None and view["current"]["operation_id"] is None
    fresh.egress_rollback(view["revision"])
    assert f"upstream socks5://naive-a1b2c3d4:{'K' * 40}@127.0.0.1:45101" in hooks.caddyfile.read_text()
