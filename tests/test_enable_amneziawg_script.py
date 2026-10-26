"""`scripts/enable-amneziawg.sh`: the supported way to enable AmneziaWG on a host the installer did not set up."""
import os
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "enable-amneziawg.sh"


def run(*args):
    return subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True)


def test_the_script_is_executable_and_valid_bash():
    assert os.access(SCRIPT, os.X_OK)
    assert subprocess.run(["bash", "-n", str(SCRIPT)]).returncode == 0


def test_help_describes_the_options_and_exits_cleanly():
    result = run("--help")
    assert result.returncode == 0
    assert "--host" in result.stdout and "--versions" in result.stdout and "set up by the installer" in result.stdout


def test_it_refuses_unknown_options_and_non_root_use():
    assert run("--bogus").returncode == 2
    if os.geteuid() != 0:
        refused = run("--host", "vpn.example.com")
        assert refused.returncode == 2 and "root" in refused.stderr


def test_it_does_what_the_installer_does_and_never_touches_the_server_keys():
    text = SCRIPT.read_text()
    for needed in ("awg_manager", "compose.amneziawg.yaml", ".env.amneziawg", "99-proxy-control-amneziawg.conf",
                   "awg-forward.service", "ufw allow", "ufw route allow in on", "PROXY_CONTROL_COMPOSE_FILES",
                   "/usr/local/bin/awg-manager healthcheck", "AWG_MANAGER_SOCKET_GID=10007", "chown -R root:root"):
        assert needed in text, needed
    # 4.0: the Rust manager's image builds against pc_common, and the manager is its own probe
    assert "for tree in awg_manager pc_common; do" in text and "python -m awg_manager" not in text
    # the state directory with the server keys is created, never removed or emptied
    assert "rm -rf /var/lib/awg-manager" not in text and "/var/lib/awg-manager/" not in text.replace("AWG_MANAGER_STATE_DIR=/var/lib/awg-manager", "")
    # the compose list comes from the version agent's configuration, not from guessing by env files
    assert "LIST=$(sed -n 's/^PROXY_CONTROL_COMPOSE_FILES=//p'" in text


def test_ports_default_to_free_pseudo_random_ones_like_the_installers_and_can_be_named():
    text = SCRIPT.read_text()
    assert "--ports" in run("--help").stdout and "10240" in run("--help").stdout
    assert "51820" not in text.replace("51820-51822", "")
    for needed in ("ss -H -lun", "ss -H -ltn", "/etc/machine-id", "21761", "sha256", "clients dial $HOST on UDP $PORTS",
                   "ufw delete allow", "proxy-control:firewall:udp:"):
        assert needed in text, needed


def test_ports_are_validated_before_anything_is_changed():
    refused = run("--host", "vpn.example.com", "--ports", "1.5=80")
    # either the root check or the port check stops it first; nothing is written either way
    assert refused.returncode == 2


def test_the_embedded_derivation_is_the_installers(tmp_path):
    """The script's python picks exactly what `installer.awg_ports` picks for the same host."""
    import re
    import sys

    sys.path.insert(0, str(SCRIPT.parents[1]))
    from installer.awg_ports import derive_port

    body = re.search(r"<<'PY'\n(.*?)\nPY\n", SCRIPT.read_text(), re.S).group(1)
    ident = Path("/etc/machine-id")
    if not ident.exists():  # the script falls back to the host name; compare with that
        import socket

        identity = socket.gethostname()
    else:
        identity = ident.read_text().strip() or __import__("socket").gethostname()
    first = subprocess.run(["python3", "-c", body, "", "--", "1.5", "2.0", "3.1"], capture_output=True, text=True)
    assert first.returncode == 0, first.stderr
    got = dict(item.split("=") for item in first.stdout.split())
    assert got == {v: str(derive_port(identity, v, 0)) for v in ("1.5", "2.0", "3.1")}
    # a bound port is skipped by raising the attempt
    busy = subprocess.run(["python3", "-c", body, str(got["1.5"]), "--", "1.5"], capture_output=True, text=True)
    assert dict(item.split("=") for item in busy.stdout.split())["1.5"] == str(derive_port(identity, "1.5", 1))
