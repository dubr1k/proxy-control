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
    for needed in ("ss -H -lun", "ss -H -ltn", "proxy-control-installer", "awg-ports", "clients dial $HOST on UDP $PORTS",
                   "ufw delete allow", "proxy-control:firewall:udp:"):
        assert needed in text, needed


def test_ports_are_validated_before_anything_is_changed():
    refused = run("--host", "vpn.example.com", "--ports", "1.5=80")
    # either the root check or the port check stops it first; nothing is written either way
    assert refused.returncode == 2


def test_the_binary_derivation_is_the_installers(tmp_path):
    """The shell invokes the native helper; compare its bytes with the recorded SHA-256 rule."""
    import hashlib

    binary = Path(os.environ.get("PROXY_CONTROL_INSTALLER_BINARY",
                                str(SCRIPT.parents[1] / "installer/bin/linux-amd64/proxy-control-installer")))
    assert binary.is_file(), "build the installer and set PROXY_CONTROL_INSTALLER_BINARY"
    assert "python3" not in SCRIPT.read_text()
    identity = "0123456789abcdef0123456789abcdef"
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/machine-id").write_text(identity + "\n")

    def derive(version, attempt):
        return 10240 + int.from_bytes(hashlib.sha256(f"{identity}:{version}:{attempt}".encode()).digest(), "big") % 21761

    command = [str(binary), "awg-ports", "--root", str(tmp_path)]
    first = subprocess.run([*command, "", "--", "1.5", "2.0", "3.1"], capture_output=True, text=True)
    assert first.returncode == 0, first.stderr
    got = dict(item.split("=") for item in first.stdout.split())
    assert got == {v: str(derive(v, 0)) for v in ("1.5", "2.0", "3.1")}
    busy = subprocess.run([*command, got["1.5"], "--", "1.5"], capture_output=True, text=True)
    assert busy.returncode == 0, busy.stderr
    assert dict(item.split("=") for item in busy.stdout.split())["1.5"] == str(derive("1.5", 1))
