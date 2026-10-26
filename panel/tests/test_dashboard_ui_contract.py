"""Static contract of the overview (v0.11): one host row, three protocol cards, no Mieru
application-bytes tile, a phone layout without horizontal scroll, and the clients badge."""

from __future__ import annotations

import json
from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "static"
DASHBOARD = (STATIC / "js/dashboard.js").read_text()
CSS = (STATIC / "style.css").read_text()







































