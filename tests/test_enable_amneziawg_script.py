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
                   "awg_manager.healthcheck", "AWG_MANAGER_SOCKET_GID=10007"):
        assert needed in text, needed
    # the state directory with the server keys is created, never removed or emptied
    assert "rm -rf /var/lib/awg-manager" not in text and "/var/lib/awg-manager/" not in text.replace("AWG_MANAGER_STATE_DIR=/var/lib/awg-manager", "")
    # the compose list comes from the version agent's configuration, not from guessing by env files
    assert "LIST=$(sed -n 's/^PROXY_CONTROL_COMPOSE_FILES=//p'" in text
