"""Reads the endpoint's per-client metrics and folds counter resets into running totals."""
from __future__ import annotations

import json
import logging
import urllib.request

LOGGER = logging.getLogger("trusttunnel_manager")


def fetch_clients(address: str, timeout: float = 3.0) -> list[dict] | None:
    """GET /clients from the loopback metrics listener; None when it is unreachable."""
    try:
        with urllib.request.urlopen(f"http://{address}/clients", timeout=timeout) as response:  # noqa: S310
            value = json.loads(response.read(4 * 1024 * 1024))
    except (OSError, ValueError):
        return None
    return value if isinstance(value, list) else None


def aggregate(rows: list[dict]) -> dict[str, dict[str, int]]:
    """Sum rows per username (the endpoint lists one row per client address)."""
    out: dict[str, dict[str, int]] = {}
    for row in rows:
        name = row.get("username") if isinstance(row, dict) else None
        if not isinstance(name, str):
            continue
        slot = out.setdefault(name, {"inbound": 0, "outbound": 0, "sessions": 0})
        for key in slot:
            value = row.get(key, 0)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                slot[key] += value
    return out


def fold(total: int, last_raw: int, reading: int) -> tuple[int, int]:
    """Return (new_total, new_last_raw). A lower reading means the counter was reset."""
    delta = reading - last_raw if reading >= last_raw else reading
    return total + delta, reading
