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
