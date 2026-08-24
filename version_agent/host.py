from __future__ import annotations

import os
import time
from pathlib import Path

# The panel container is read-only, capability-stripped and mounts nothing from
# the host but the agent socket, so it cannot see host CPU, memory or disk at
# all. This agent already runs on the host, so it is the only sanctioned place
# to read them from — and it reads, never acts, so it grants no new privilege.

_PROC = Path("/proc")
_ROOT = "/"

# Utilisation is a rate, so it needs two samples. The window is short enough to
# stay inside one dashboard request and long enough to survive scheduler jitter.
_SAMPLE_SECONDS = 0.15


def _cpu_times() -> tuple[int, int] | None:
    """Total and idle jiffies from the aggregate `cpu` line of /proc/stat."""
    try:
        first_line = _PROC.joinpath("stat").read_text().split("\n", 1)[0]
    except OSError:
        return None
    fields = first_line.split()
    if len(fields) < 6 or fields[0] != "cpu":
        return None
    try:
        values = [int(value) for value in fields[1:]]
    except ValueError:
        return None
    # idle + iowait: time the CPU had nothing runnable, not time it was absent.
    return sum(values), values[3] + values[4]


def _cpu() -> dict | None:
    first = _cpu_times()
    if first is None:
        return None
    time.sleep(_SAMPLE_SECONDS)
    second = _cpu_times()
    if second is None:
        return None
    total = second[0] - first[0]
    idle = second[1] - first[1]
    result: dict = {"cores": os.cpu_count(), "load_average": _load_average()}
    # A counter that did not advance says nothing; reporting 0% would be a lie.
    result["used_percent"] = (
        round(min(100.0, max(0.0, 100.0 * (total - idle) / total)), 1)
        if total > 0
        else None
    )
    return result


def _load_average() -> list[float] | None:
    try:
        fields = _PROC.joinpath("loadavg").read_text().split()[:3]
        return [round(float(value), 2) for value in fields]
    except (OSError, ValueError, IndexError):
        return None


def _memory() -> dict | None:
    try:
        lines = _PROC.joinpath("meminfo").read_text().splitlines()
    except OSError:
        return None
    values: dict[str, int] = {}
    for line in lines:
        key, _, rest = line.partition(":")
        fields = rest.split()
        if fields and fields[0].isdigit():
            values[key] = int(fields[0]) * 1024
    total = values.get("MemTotal")
    available = values.get("MemAvailable")
    if not total or available is None:
        return None
    # MemAvailable, not MemFree: cache the kernel can reclaim on demand is not
    # memory pressure, and reporting it as used makes every server look full.
    available = min(available, total)
    return {
        "total_bytes": total,
        "available_bytes": available,
        "used_bytes": total - available,
        "used_percent": round(100.0 * (total - available) / total, 1),
    }


def _disk(path: str = _ROOT) -> dict | None:
    try:
        stats = os.statvfs(path)
    except OSError:
        return None
    total = stats.f_blocks * stats.f_frsize
    if total <= 0:
        return None
    # f_bavail excludes the root-reserved margin, so it is what an operator can
    # actually still write; f_bfree would promise space they cannot use.
    available = stats.f_bavail * stats.f_frsize
    used = total - stats.f_bfree * stats.f_frsize
    return {
        "total_bytes": total,
        "available_bytes": available,
        "used_bytes": used,
        "used_percent": round(100.0 * used / total, 1),
    }


def host_metrics() -> dict:
    """Read-only host telemetry: CPU utilisation, memory and root filesystem.

    Every section degrades to null independently, because a kernel that stops
    exposing one of these files must not blank the whole card.
    """
    return {"cpu": _cpu(), "memory": _memory(), "disk": _disk()}
