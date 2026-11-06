"""The actual shared dialog controller cannot carry approvals between openings."""
import subprocess
from pathlib import Path


def test_queued_close_and_return_value_are_isolated_per_dialog_opening():
    completed = subprocess.run(
        ["node", str(Path(__file__).with_name("dialog_lifecycle.mjs"))],
        capture_output=True, text=True, timeout=20,
    )
    assert completed.returncode == 0, completed.stderr
