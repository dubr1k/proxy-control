"""The capability matrix must be explicit: every cell is a decision, not a blank.

`unsupported` and `unproven` are answers. A missing cell is not, which is why
this test refuses a fixture that omits one.
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/vnext-capabilities.json"
CAPABILITIES = (
    "create", "enable", "disable", "rotate", "delete", "quota", "expiry", "accounting",
    "stable_access_artifact", "credential_capture_without_rotation", "whole_service_socks_upstream",
    "cidr_routing", "domain_routing", "per_client_routing", "hot_reload", "rollback",
    "dns_ownership", "socks_hostname_propagation", "tcp_udp_upstream", "identity_propagation",
    "fail_closed", "binary_hot_upgrade", "exact_geodata_version",
)
STATUSES = {"supported", "unsupported", "unproven", "out_of_scope"}


def test_every_cell_is_explicit_and_required_conclusions_hold():
    data = json.loads(FIXTURE.read_text())
    assert data["schema"] == 1
    assert tuple(data["columns"]) == CAPABILITIES
    assert set(data["rows"]) == {"fleet_v1", "mtproxy", "naive", "mieru"}
    for protocol, cells in data["rows"].items():
        assert set(cells) == set(CAPABILITIES), protocol
        for name, cell in cells.items():
            assert cell["status"] in STATUSES, (protocol, name)
            assert cell["note"].strip(), (protocol, name)
    rows = data["rows"]
    assert rows["fleet_v1"]["create"]["status"] == "unsupported"
    assert rows["naive"]["whole_service_socks_upstream"]["status"] == "supported"
    assert rows["naive"]["per_client_routing"]["status"] == "unproven"
    assert rows["mieru"]["domain_routing"]["status"] == "unproven"
    assert rows["mieru"]["credential_capture_without_rotation"]["status"] == "unsupported"
    assert rows["mtproxy"]["credential_capture_without_rotation"]["status"] == "supported"
    for routing in ("cidr_routing", "domain_routing", "per_client_routing", "whole_service_socks_upstream"):
        assert rows["mtproxy"][routing]["status"] == "out_of_scope"


def test_named_client_matrix_is_explicit_and_matches_the_owner_decision():
    clients = json.loads(FIXTURE.read_text())["clients"]
    assert set(clients) == {
        "karing", "mihomo", "singbox", "mieru_cli", "telegram",
        "shadowrocket", "nekobox", "v2rayn", "hiddify",
    }
    for name, cells in clients.items():
        assert set(cells) == {"mtproxy", "naive", "mieru"}, name
        for protocol, cell in cells.items():
            assert cell["status"] in STATUSES and cell["note"].strip(), (name, protocol)
    assert clients["karing"]["naive"]["status"] == "supported"
    assert clients["karing"]["mieru"]["status"] == "supported"
    assert clients["singbox"]["naive"]["status"] == "supported"      # sing-box 1.13.0, outbound naive
    assert clients["singbox"]["mieru"]["status"] == "unsupported"     # no mieru outbound
    assert clients["mihomo"]["mieru"]["status"] == "supported"        # type: mieru
    assert clients["mihomo"]["naive"]["status"] == "unsupported"      # MetaCubeX/mihomo#273
    assert clients["mieru_cli"]["mieru"]["status"] == "unsupported"   # the client has no subscriptions
    assert all(cells["mtproxy"]["status"] == "unsupported" for cells in clients.values())
