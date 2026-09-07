"""The firewall boundary: never lock the operator out."""
from __future__ import annotations

import subprocess

import pytest

def test_an_inactive_ufw_is_enabled_only_after_ssh_is_allowed():
    """Enabling a default-deny firewall before allowing SSH locks the operator
    out of the server it is installing on. The order is the whole safety
    property, so it is asserted rather than assumed."""
    from installer.adapters.firewall import enable_ufw

    calls: list[tuple[str, ...]] = []

    def run(argv):
        calls.append(tuple(str(value) for value in argv))
        return subprocess.CompletedProcess(argv, 0, "", "")

    enable_ufw(run, ssh_port=22)

    allow = next(i for i, call in enumerate(calls) if call[:2] == ("ufw", "allow"))
    enable = next(i for i, call in enumerate(calls) if "enable" in call)
    assert allow < enable
    assert "22" in calls[allow]


def test_enabling_ufw_stops_if_allowing_ssh_fails():
    """A firewall enabled after a failed allow is a locked door with the key
    inside."""
    from installer.adapters.firewall import FirewallError, enable_ufw

    calls: list[tuple[str, ...]] = []

    def run(argv):
        command = tuple(str(value) for value in argv)
        calls.append(command)
        code = 1 if command[:2] == ("ufw", "allow") else 0
        return subprocess.CompletedProcess(argv, code, "", "refused")

    with pytest.raises(FirewallError, match="SSH"):
        enable_ufw(run, ssh_port=22)

    assert not any("enable" in call for call in calls)


def test_preparing_an_enable_does_not_demand_an_active_firewall():
    """The enable happens while applying, so preparing runs against a firewall
    that is still off. Reading its rules there is asking a question the host
    cannot answer yet."""
    from installer.adapters.firewall import FirewallAdapter
    from installer.planner import Action

    action = Action(
        id="firewall.ufw",
        adapter="firewall",
        owner="proxy-control:firewall",
        mutations=("ssh=22", "ipv6=false", "enable=true", "rule=tcp:443"),
        preconditions=("the SSH listener is preserved before the firewall denies",),
        verification=("exact selected-profile UFW rules are active",),
        inverse=("delete exact comment-scoped rules added by this action",),
        credentials_required=False,
    )

    class Runner:
        def run(self, argv):
            del argv
            raise AssertionError("an inactive firewall must not be queried")

    adapter = FirewallAdapter(runner=Runner())
    # The IPv6 mode is read from the host and is not what this test is about.
    adapter._assert_ipv6_mode = lambda enabled: enabled

    checkpoint = adapter.prepare(action)

    assert checkpoint["preexisting"] == ()
    assert checkpoint["initial_fingerprints"] == ()
