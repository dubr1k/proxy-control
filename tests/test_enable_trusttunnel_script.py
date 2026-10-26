"""Public shell entrypoint input handling; lifecycle coverage is native Cargo."""
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/enable-trusttunnel.sh"


@pytest.mark.parametrize("arguments", [["--help"], ["--bogus"]])
def test_cli_returns_without_mutating_host_on_help_or_invalid_input(arguments):
    result = subprocess.run(["bash", str(SCRIPT), *arguments], capture_output=True, text=True, timeout=10)
    assert result.returncode == (0 if arguments == ["--help"] else 2)
