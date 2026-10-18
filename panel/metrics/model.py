"""Names and limits shared by the metrics modules: series ids, ranges, resolutions."""
from __future__ import annotations

from typing import Protocol

LOCAL_NODE = "local"
PROTOCOLS = ("mtproxy", "naive", "mieru", "amneziawg", "trusttunnel")
HOST_SERIES = (
    "host.cpu", "host.mem", "host.swap", "host.disk", "host.disk_read_bps", "host.disk_write_bps",
    "host.load1", "net.rx_bps", "net.tx_bps",
)
PROTOCOL_SERIES = ("up_bps", "down_bps", "sessions", "clients", "up_bytes", "down_bytes")
ALL_SERIES = HOST_SERIES + tuple(f"{p}.{s}" for p in PROTOCOLS for s in PROTOCOL_SERIES)

RANGES = {"15m": 900, "1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800, "30d": 2592000, "90d": 7776000}
# Rollup resolution (seconds) -> how long its buckets are kept.
RETENTION = {60: 3 * 86400, 900: 35 * 86400, 3600: 400 * 86400}
POINTS_MIN, POINTS_MAX, POINTS_DEFAULT = 10, 2000, 240

# A protocol counter that only grows is a "bytes" series: its rollup `sum` is the volume.
def is_bytes_series(series: str) -> bool:
    return series.endswith("_bytes")


def resolution_for(range_seconds: int) -> int:
    """The rollup resolution that serves a range: 60 s up to 3 d, 900 s up to 35 d, 3600 s beyond."""
    if range_seconds <= 3 * 86400:
        return 60
    if range_seconds <= 35 * 86400:
        return 900
    return 3600


class NodeMetricsSource(Protocol):
    """What wave 2 (fleet fan-out) plugs in to serve the linked nodes' meters.

    Every method answers `None` (or an empty list) when the node cannot be served; the
    caller then reports the node as `unavailable`/`unsupported`."""

    async def live(self, node_id: str) -> dict | None:
        """One node entry of the live snapshot (`nodes[i]` of `/api/metrics/live`)."""

    async def history(self, node_id: str, series: list[str], range: str, points: int) -> dict | None:
        """The body of `/api/metrics/history` for that node."""

    async def summary(self, node_id: str, range: str) -> dict | None:
        """The summary row of that node (a `nodes[i]` of `/api/metrics/summary`)."""

    async def nodes(self) -> list[dict]:
        """The nodes this source can serve: `[{node_id, name}]`."""
