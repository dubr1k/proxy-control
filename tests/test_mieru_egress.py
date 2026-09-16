"""`mieru_manager/egress.py` and the manager's egress API (v0.4): the compiled document ↔
mita's `egress` section, applied in restart mode through the existing transaction."""
from __future__ import annotations

import json

import pytest

from mieru_manager import egress
from mieru_manager.egress import EgressInvalid, EgressUnreachable, from_mita, to_mita, validate_document
from mieru_manager.service import ConfigConflict, MieruManager, MitaError
from tests.test_mieru_manager import BASE, FakeMita

WARP = "socks5://127.0.0.1:45000"
DIRECT_DOC = {"schema": 1, "proxies": [], "rules": []}
WARP_DOC = {"schema": 1, "proxies": [{"name": "warp", "provider": "warp"}],
            "rules": [{"domains": ["*"], "cidrs": ["*"], "action": "PROXY", "proxy": "warp"}]}
SELECTIVE_DOC = {"schema": 1, "proxies": [{"name": "warp", "provider": "warp"}], "rules": [
    {"domains": ["example.com"], "cidrs": [], "action": "REJECT", "proxy": None},
    {"domains": ["api.ipify.org"], "cidrs": ["10.0.0.0/8"], "action": "DIRECT", "proxy": None},
    {"domains": ["*"], "cidrs": ["*"], "action": "PROXY", "proxy": "warp"},
]}


# --- documents ---

def test_validate_document_normalises_and_bounds():
    normalised = validate_document({"schema": 1, "proxies": [{"name": "warp", "provider": "warp"}], "rules": [
        {"domains": ["Example.COM."], "cidrs": ["10.1.2.3/8"], "action": "PROXY", "proxy": "warp"}]})
    assert normalised["rules"] == [{"domains": ["example.com"], "cidrs": ["10.0.0.0/8"], "action": "PROXY", "proxy": "warp"}]
    for bad in (
        {"schema": 2, "proxies": [], "rules": []},
        {"schema": 1, "proxies": [], "rules": [], "extra": 1},
        {"schema": 1, "proxies": [{"name": "other", "provider": "warp"}], "rules": []},
        {"schema": 1, "proxies": [{"name": "warp", "provider": "warp", "host": "x"}], "rules": []},
        {"schema": 1, "proxies": [], "rules": [{"domains": ["a.example"], "cidrs": [], "action": "PROXY", "proxy": "warp"}]},
        {"schema": 1, "proxies": [], "rules": [{"domains": ["a.example"], "cidrs": [], "action": "DIRECT", "proxy": "warp"}]},
        {"schema": 1, "proxies": [], "rules": [{"domains": [], "cidrs": [], "action": "REJECT", "proxy": None}]},
        {"schema": 1, "proxies": [], "rules": [{"domains": ["bad host"], "cidrs": [], "action": "REJECT", "proxy": None}]},
        {"schema": 1, "proxies": [], "rules": [{"domains": [], "cidrs": ["10.0.0.0/33"], "action": "REJECT", "proxy": None}]},
        {"schema": 1, "proxies": [], "rules": [{"domains": ["a.example"], "cidrs": [], "action": "ALLOW", "proxy": None}]},
        {"schema": 1, "proxies": [], "rules": [{"domains": ["a.example"], "cidrs": [], "action": "REJECT", "proxy": None}] * (egress.MAX_RULES + 1)},
    ):
        with pytest.raises(EgressInvalid):
            validate_document(bad)


def test_to_mita_renders_first_match_rules_and_the_provider_endpoint():
    assert to_mita(validate_document(DIRECT_DOC), None) == {}  # no egress key: mita's default is DIRECT
    section = to_mita(validate_document(SELECTIVE_DOC), WARP)
    assert section == {
        "proxies": [{"name": "warp", "protocol": "SOCKS5_PROXY_PROTOCOL", "host": "127.0.0.1", "port": 45000}],
        "rules": [
            {"action": "REJECT", "domainNames": ["example.com"]},
            {"action": "DIRECT", "ipRanges": ["10.0.0.0/8"], "domainNames": ["api.ipify.org"]},
            {"action": "PROXY", "ipRanges": ["*"], "domainNames": ["*"], "proxyNames": ["warp"]},
        ],
    }
    with pytest.raises(EgressInvalid, match="not configured"):
        to_mita(validate_document(WARP_DOC), None)
    with pytest.raises(EgressInvalid, match="socks5"):
        to_mita(validate_document(WARP_DOC), "http://127.0.0.1:8118")


def test_from_mita_round_trips_and_reports_a_foreign_proxy_as_custom():
    for document in (DIRECT_DOC, WARP_DOC, SELECTIVE_DOC):
        normalised = validate_document(document)
        assert from_mita(to_mita(normalised, WARP), WARP) == normalised
    assert from_mita(None, WARP) == validate_document(DIRECT_DOC)
    installer_seed = {"proxies": [{"name": "warp", "protocol": "SOCKS5_PROXY_PROTOCOL", "host": "127.0.0.1", "port": 40000}],
                      "rules": [{"ipRanges": ["0.0.0.0/0", "::/0"], "action": "DIRECT"}]}
    assert from_mita(installer_seed, "socks5://127.0.0.1:40000") == validate_document(
        {"schema": 1, "proxies": [{"name": "warp", "provider": "warp"}],
         "rules": [{"domains": [], "cidrs": ["0.0.0.0/0", "::/0"], "action": "DIRECT", "proxy": None}]})
    assert from_mita(installer_seed, WARP) is None  # another port: not this host's provider
    assert from_mita({"proxies": [{"name": "warp", "protocol": "SOCKS5_PROXY_PROTOCOL", "host": "127.0.0.1", "port": 45000,
                                   "socks5Authentication": {"user": "u", "password": "p"}}], "rules": []}, WARP) is None
    assert from_mita({"proxies": [], "rules": [{"action": "PROXY", "proxyNames": ["x"]}]}, WARP) is None


# --- the manager ---

def _manager(tmp_path, mita=None, provider=WARP, reachable=True):
    service = MieruManager(mita=mita or FakeMita(), state_dir=tmp_path / "state", public_host="proxy.example.com",
                           provider_url=provider)
    service.reachability = lambda url, timeout=3.0: reachable
    service.bootstrap()
    return service


def test_get_reports_the_section_document_providers_and_capabilities(tmp_path):
    service = _manager(tmp_path)
    view = service.egress()
    assert view["document"] == validate_document(DIRECT_DOC) and view["mode"] == "direct"
    assert view["raw"] is None and view["managed"] is False
    assert view["providers"] == {"warp": {"url": WARP, "reachable": True}}
    assert view["capabilities"] == list(egress.CAPABILITIES) and view["restart_required"] is True
    assert view["revision"] == service.inspect()["revision"] and view["previous"] is None
    seeded = FakeMita({**BASE, "egress": {"proxies": [{"name": "warp", "protocol": "SOCKS5_PROXY_PROTOCOL", "host": "127.0.0.1",
                                                          "port": 40000}], "rules": [{"ipRanges": ["*"], "action": "PROXY", "proxyNames": ["warp"]}]}})
    custom = _manager(tmp_path / "custom", seeded).egress()
    assert custom["mode"] == "custom" and custom["document"] is None and custom["raw"]["proxies"][0]["port"] == 40000
    assert _manager(tmp_path / "none", provider=None).egress()["providers"] == {}


def test_plan_is_read_only_and_reports_the_target_section(tmp_path):
    mita = FakeMita()
    service = _manager(tmp_path, mita)
    revision = service.inspect()["revision"]
    plan = service.egress_plan(revision, WARP_DOC)
    assert mita.calls == [] and mita.observe() == BASE
    assert plan["revision"] == revision and plan["restart_required"] is True
    assert plan["target"] == to_mita(validate_document(WARP_DOC), WARP) and plan["reachability"] == {"warp": True}
    assert any("warp" in line for line in plan["diff"])


def test_apply_replaces_only_the_egress_section_with_a_restart(tmp_path):
    mita = FakeMita()
    service = _manager(tmp_path, mita)
    revision = service.create_user("bob", [], expected_revision=service.inspect()["revision"])["revision"]
    before = mita.observe()
    mita.calls.clear()
    result = service.egress_apply(revision, SELECTIVE_DOC, "routing:p1:1")
    after = mita.observe()
    assert after["egress"] == to_mita(validate_document(SELECTIVE_DOC), WARP)
    assert {k: v for k, v in after.items() if k != "egress"} == {k: v for k, v in before.items() if k != "egress"}
    assert mita.calls[-3:] == [("stop",), ("start",), ("probe",)]
    assert result["revision"] == service.inspect()["revision"] != revision
    assert result["applied"] == validate_document(SELECTIVE_DOC) and result["replayed"] is False
    view = service.egress()
    assert view["document"] == validate_document(SELECTIVE_DOC) and view["mode"] == "proxy" and view["managed"] is True
    assert view["previous"] is not None
    state = json.loads((tmp_path / "state" / "state.json").read_text())
    assert state["egress"]["history"][-1]["operation_id"] == "routing:p1:1" and len(state["egress"]["history"]) == 2


def test_apply_conflicts_and_refusals_leave_mita_untouched(tmp_path):
    mita = FakeMita()
    service = _manager(tmp_path, mita, reachable=False)
    revision = service.inspect()["revision"]
    with pytest.raises(ConfigConflict, match="revision"):
        service.egress_apply("0" * 64, WARP_DOC, "op-1")
    with pytest.raises(EgressUnreachable):
        service.egress_apply(revision, WARP_DOC, "op-1")
    with pytest.raises(EgressInvalid):
        service.egress_apply(revision, {"schema": 1, "proxies": [], "rules": [{"domains": [], "cidrs": [], "action": "REJECT", "proxy": None}]}, "op-1")
    assert mita.calls == [] and mita.observe() == BASE
    result = service.egress_apply(revision, DIRECT_DOC, "op-2")  # direct never needs the provider
    assert result["applied"] == validate_document(DIRECT_DOC)
    (tmp_path / "none").mkdir()
    without = _manager(tmp_path / "none", provider=None)
    with pytest.raises(EgressInvalid, match="not configured"):
        without.egress_apply(without.inspect()["revision"], WARP_DOC, "op-3")


def test_apply_is_idempotent_by_operation_id(tmp_path):
    mita = FakeMita()
    service = _manager(tmp_path, mita)
    first = service.egress_apply(service.inspect()["revision"], WARP_DOC, "op-1")
    applied = [call for call in mita.calls if call[0] == "apply"]
    again = service.egress_apply(first["revision"], WARP_DOC, "op-1")
    assert again["revision"] == first["revision"] and again["replayed"] is True
    assert [call for call in mita.calls if call[0] == "apply"] == applied
    with pytest.raises(ConfigConflict, match="operation id"):
        service.egress_apply(first["revision"], DIRECT_DOC, "op-1")


def test_a_failed_probe_rolls_the_section_back(tmp_path):
    mita = FakeMita()
    service = _manager(tmp_path, mita)
    revision = service.inspect()["revision"]
    mita.fail_probe = True
    with pytest.raises(MitaError, match="rolled back"):
        service.egress_apply(revision, WARP_DOC, "op-1")
    assert mita.observe() == BASE and service.inspect()["revision"] == revision
    assert service.egress()["previous"] is None


def test_rollback_walks_back_to_the_seeded_section(tmp_path):
    seed = {**BASE, "egress": {"proxies": [{"name": "warp", "protocol": "SOCKS5_PROXY_PROTOCOL", "host": "127.0.0.1", "port": 40000}],
                               "rules": [{"ipRanges": ["0.0.0.0/0", "::/0"], "action": "DIRECT"}]}}
    mita = FakeMita(seed)
    service = _manager(tmp_path, mita)
    first = service.egress_apply(service.inspect()["revision"], WARP_DOC, "op-1")
    second = service.egress_apply(first["revision"], SELECTIVE_DOC, "op-2")
    rolled = service.egress_rollback(second["revision"])
    assert service.egress()["document"] == validate_document(WARP_DOC) and rolled["applied"] == validate_document(WARP_DOC)
    rolled = service.egress_rollback(rolled["revision"])
    assert mita.observe()["egress"] == seed["egress"]  # the seeded section, verbatim
    assert service.egress()["mode"] == "custom" and rolled["applied"] is None
    with pytest.raises(ConfigConflict, match="no previous"):
        service.egress_rollback(rolled["revision"])


# --- the router provider (v0.5) ---

ROUTER = "socks5://127.0.0.1:45102"
ROUTER_DOC = {"schema": 1, "proxies": [{"name": "router", "provider": "router"}],
              "rules": [{"domains": ["*"], "cidrs": ["*"], "action": "PROXY", "proxy": "router"}]}
ROUTER_SECRET = "mieru-e5f6a7b8:" + "K" * 40


def _router_manager(tmp_path, mita=None, *, secret=ROUTER_SECRET, reachable=True):
    credential = tmp_path / "xray-router-ingress"
    credential.write_text(secret + "\n")
    service = MieruManager(mita=mita or FakeMita(), state_dir=tmp_path / "state", public_host="proxy.example.com",
                           provider_url=WARP, router_url=ROUTER, router_credential_file=credential)
    service.greetings = []
    service.reachability = lambda url, timeout=3.0, auth=False: (service.greetings.append((url, auth)), reachable)[1]
    service.bootstrap()
    return service


def test_to_mita_router_proxy_has_socks5_authentication():
    section = to_mita(validate_document(ROUTER_DOC), {"warp": WARP, "router": ROUTER},
                      {"router": ("mieru-e5f6a7b8", "K" * 40)})
    assert section["proxies"] == [{"name": "router", "protocol": "SOCKS5_PROXY_PROTOCOL", "host": "127.0.0.1", "port": 45102,
                                   "socks5Authentication": {"user": "mieru-e5f6a7b8", "password": "K" * 40}}]
    assert section["rules"] == [{"action": "PROXY", "ipRanges": ["*"], "domainNames": ["*"], "proxyNames": ["router"]}]
    with pytest.raises(EgressInvalid, match="credential"):
        to_mita(validate_document(ROUTER_DOC), {"warp": WARP, "router": ROUTER})
    with pytest.raises(EgressInvalid, match="router is not configured"):
        to_mita(validate_document(ROUTER_DOC), {"warp": WARP, "router": None}, {"router": ("u", "p" * 16)})


def test_from_mita_router_with_auth_is_the_router_document():
    section = to_mita(validate_document(ROUTER_DOC), {"warp": WARP, "router": ROUTER}, {"router": ("u", "p" * 16)})
    assert from_mita(section, {"warp": WARP, "router": ROUTER}) == validate_document(ROUTER_DOC)
    # Without a credential the router proxy is somebody else's; with one, warp is not warp.
    bare = {"proxies": [{"name": "router", "protocol": "SOCKS5_PROXY_PROTOCOL", "host": "127.0.0.1", "port": 45102}], "rules": []}
    assert from_mita(bare, {"warp": WARP, "router": ROUTER}) is None
    assert from_mita(section, WARP) is None  # a v0.4 host without a router
    assert egress.router_credential_stale(section, ("u", "p" * 16)) is False
    assert egress.router_credential_stale(section, ("u", "q" * 16)) is True
    masked = egress.redact_section(section)
    assert masked["proxies"][0]["socks5Authentication"] == {"user": "***", "password": "***"}
    assert section["proxies"][0]["socks5Authentication"]["password"] == "p" * 16


def test_egress_views_never_contain_router_credential(tmp_path):
    mita = FakeMita()
    service = _router_manager(tmp_path, mita)
    revision = service.inspect()["revision"]
    plan = service.egress_plan(revision, ROUTER_DOC)
    assert plan["reachability"] == {"router": True} and (ROUTER, True) in service.greetings
    result = service.egress_apply(revision, ROUTER_DOC, "op-router")
    assert mita.observe()["egress"]["proxies"][0]["socks5Authentication"] == {"user": "mieru-e5f6a7b8", "password": "K" * 40}
    view = service.egress()
    assert view["document"] == validate_document(ROUTER_DOC) and view["mode"] == "proxy"
    assert view["providers"]["router"] == {"url": ROUTER, "reachable": True}
    for text in (json.dumps(plan), json.dumps(view), json.dumps(result),
                 json.dumps(service.egress_plan(view["revision"], WARP_DOC))):
        assert "K" * 40 not in text and "mieru-e5f6a7b8" not in text
    assert "K" * 40 not in (tmp_path / "state" / "state.json").read_text()


def test_apply_router_unreachable_refuses(tmp_path):
    mita = FakeMita()
    service = _router_manager(tmp_path, mita, reachable=False)
    with pytest.raises(EgressUnreachable, match="router"):
        service.egress_apply(service.inspect()["revision"], ROUTER_DOC, "op-1")
    assert "egress" not in mita.observe()
    plain = _manager(tmp_path / "plain")
    with pytest.raises(EgressInvalid, match="router"):
        plain.egress_apply(plain.inspect()["revision"], ROUTER_DOC, "op-1")


def test_bootstrap_rerenders_after_rotation(tmp_path):
    mita = FakeMita()
    service = _router_manager(tmp_path, mita)
    applied = service.egress_apply(service.inspect()["revision"], ROUTER_DOC, "op-router")
    (tmp_path / "xray-router-ingress").write_text("mieru-e5f6a7b8:" + "Z" * 40 + "\n")
    assert service.egress()["warnings"] == ["router_credential_stale"]
    mita.calls.clear()
    fresh = _router_manager(tmp_path, mita, secret="mieru-e5f6a7b8:" + "Z" * 40)
    assert mita.observe()["egress"]["proxies"][0]["socks5Authentication"]["password"] == "Z" * 40
    assert ("stop",) in mita.calls and ("start",) in mita.calls
    view = fresh.egress()
    assert view["warnings"] == [] and view["document"] == validate_document(ROUTER_DOC)
    assert view["revision"] != applied["revision"] and view["current"]["operation_id"] == "op-router"
    assert view["previous"] is not None
    # A rollback still walks back: the floor (no section) is restored.
    fresh.egress_rollback(view["revision"])
    assert "egress" not in mita.observe()
    # A custom hand-written router proxy with somebody's credential is shown masked.
    custom = FakeMita({**BASE, "egress": {"proxies": [{"name": "router", "protocol": "SOCKS5_PROXY_PROTOCOL", "host": "127.0.0.1",
                                                        "port": 45102, "socks5Authentication": {"user": "x", "password": "y" * 20}}],
                                          "rules": [{"ipRanges": ["*"], "action": "PROXY", "proxyNames": ["router"]}]}})
    other = _manager(tmp_path / "custom", custom)
    assert other.egress()["mode"] == "custom" and "y" * 20 not in json.dumps(other.egress())


def test_bootstrap_refreshes_the_installer_seed_after_rotation(tmp_path):
    """The installer seeds mita's `egress` with the router proxy and the credential of the day
    (v0.5); there is no journal yet. After a rotation bootstrap re-renders the section from the
    file through the restart transaction, exactly as it does for an applied one."""
    seeded = FakeMita({**BASE, "egress": {
        "proxies": [{"name": "router", "protocol": "SOCKS5_PROXY_PROTOCOL", "host": "127.0.0.1", "port": 45102,
                     "socks5Authentication": {"user": "mieru-e5f6a7b8", "password": "K" * 40}}],
        "rules": [{"action": "PROXY", "ipRanges": ["*"], "domainNames": ["*"], "proxyNames": ["router"]}]}})
    service = _router_manager(tmp_path, seeded)
    view = service.egress()
    assert view["mode"] == "proxy" and view["document"] == validate_document(ROUTER_DOC)
    assert view["warnings"] == ["adopts_unmanaged_egress"]  # the seed: nothing applied by the manager yet
    (tmp_path / "xray-router-ingress").write_text("mieru-e5f6a7b8:" + "Z" * 40 + "\n")
    assert "router_credential_stale" in service.egress()["warnings"]
    seeded.calls.clear()
    fresh = _router_manager(tmp_path, seeded, secret="mieru-e5f6a7b8:" + "Z" * 40)
    assert seeded.observe()["egress"]["proxies"][0]["socks5Authentication"]["password"] == "Z" * 40
    assert ("stop",) in seeded.calls and ("start",) in seeded.calls
    view = fresh.egress()
    assert "router_credential_stale" not in view["warnings"] and view["document"] == validate_document(ROUTER_DOC)
