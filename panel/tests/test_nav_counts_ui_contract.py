"""The sidebar badges (owner, 2026-10-18: «количество клиентов появляется только после того как
я нажму, при старте панели у всех черточки»): every badge is painted at start-up from one
place, whichever section the panel opens on, and kept fresh while the tab is visible."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

JS = Path(__file__).resolve().parent.parent / "static/js"
NODE = shutil.which("node")




