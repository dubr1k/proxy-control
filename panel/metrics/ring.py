"""In-memory points per series: a fixed-size deque of (ts, value) and the latest snapshot.

Single asyncio thread only: readers copy a deque on the loop, never from a worker thread."""
from __future__ import annotations

from collections import deque


class SeriesRing:
    def __init__(self, points: int = 900):
        self.points = max(2, int(points))
        self._series: dict[str, deque] = {}
        self.snapshot: dict | None = None

    def append(self, series: str, ts: float, value: float) -> None:
        ring = self._series.get(series)
        if ring is None:
            ring = self._series[series] = deque(maxlen=self.points)
        ring.append((ts, float(value)))

    def add_sample(self, ts: float, values: dict[str, float | None]) -> None:
        for series, value in values.items():
            if value is not None:
                self.append(series, ts, value)

    def points_of(self, series: str, start: float = 0.0, end: float = float("inf")) -> list[tuple[float, float]]:
        ring = self._series.get(series)
        if not ring:
            return []
        return [(ts, value) for ts, value in list(ring) if start <= ts <= end]

    def oldest(self, series: str | None = None) -> float | None:
        names = [series] if series else list(self._series)
        firsts = [self._series[n][0][0] for n in names if self._series.get(n)]
        return min(firsts) if firsts else None

    def series_names(self) -> list[str]:
        return list(self._series)

    def last(self, series: str) -> tuple[float, float] | None:
        ring = self._series.get(series)
        return ring[-1] if ring else None
