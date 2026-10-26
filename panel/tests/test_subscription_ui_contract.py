"""The client window's contract with the API and with the operator.

The UI is plain ES modules without a build step, so this checks the source it ships:
the reveal path behind the «Показать» button, the destructive actions going through
confirmation, the node × protocol matrix and its diff, the per-client link variants,
and the warning that some clients never refresh on their own.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
























