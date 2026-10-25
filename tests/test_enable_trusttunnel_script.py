"""`scripts/enable-trusttunnel.sh`: the supported way to enable TrustTunnel on a host the installer did not set up."""
import os
import subprocess
from pathlib import Path

from installer.adapters.trusttunnel import TT_SHA256_AARCH64

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "enable-trusttunnel.sh"


def run(*args):
    return subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True)


def test_the_script_is_executable_and_valid_bash():
    assert os.access(SCRIPT, os.X_OK)
    assert subprocess.run(["bash", "-n", str(SCRIPT)]).returncode == 0


def test_help_describes_the_options_and_exits_cleanly():
    result = run("--help")
    assert result.returncode == 0
    assert "--host" in result.stdout and "--listen-port" in result.stdout and "set up by the installer" in result.stdout
    assert "TCP only" in result.stdout and "no firewall rule" in result.stdout


def test_it_refuses_unknown_options_and_non_root_use():
    assert run("--bogus").returncode == 2
    if os.geteuid() != 0:
        refused = run("--host", "gate.example.org")
        assert refused.returncode == 2 and "root" in refused.stderr


def test_the_script_writes_the_installers_env_contract():
    text = SCRIPT.read_text()
    for name in ("TRUSTTUNNEL_MANAGER_TOKEN_FILE", "TT_MANAGER_STATE_DIR", "TT_CERT_DIR=/etc/letsencrypt", "TT_HOSTNAME",
                 "TT_LISTEN", "TT_VERSION=v", "TT_SHA256_X86_64", f"TT_SHA256_AARCH64={TT_SHA256_AARCH64}",
                 "TRUSTTUNNEL_MANAGER_SOCKET_GID=10008", "TRUSTTUNNEL_PUBLIC_HOST", "compose.trusttunnel.yaml",
                 ".env.trusttunnel"):
        assert name in text, name
    assert "ufw" not in text.replace("no firewall rule", "")
    assert "for tree in trusttunnel_manager pc_common; do" in text
    assert "/usr/local/bin/trusttunnel-manager healthcheck" in text and "python -m trusttunnel_manager" not in text
